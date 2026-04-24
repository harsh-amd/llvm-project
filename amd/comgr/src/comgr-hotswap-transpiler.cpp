//===- comgr-hotswap-transpiler.cpp - Cross-family ISA transpile pipeline --===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

// ── Transpile Mapping JSON Emission ──────────────────────────────────────────

void TranspileMapping::emitJSON(const std::string &path) const {
  FILE *fp = fopen(path.c_str(), "w");
  if (!fp) return;
  fprintf(fp, "{\n");
  fprintf(fp, "  \"source_isa\": \"%s\",\n", source_isa.c_str());
  fprintf(fp, "  \"target_isa\": \"%s\",\n", target_isa.c_str());
  fprintf(fp, "  \"kernel\": \"%s\",\n", kernel.c_str());
  fprintf(fp, "  \"entries\": [\n");
  for (size_t i = 0; i < entries.size(); ++i) {
    const auto &e = entries[i];
    fprintf(fp, "    {\"src_offset\": %lu, \"src_mnemonic\": \"%s\", \"src_size\": %u, "
            "\"kind\": \"%s\", \"tgt_count\": %u, \"tgt_offsets\": [",
            (unsigned long)e.src_offset, e.src_mnemonic.c_str(), e.src_size,
            e.kind.c_str(), e.tgt_count);
    for (size_t j = 0; j < e.tgt_offsets.size(); ++j) {
      if (j > 0) fprintf(fp, ", ");
      fprintf(fp, "%lu", (unsigned long)e.tgt_offsets[j]);
    }
    fprintf(fp, "]}%s\n", i + 1 < entries.size() ? "," : "");
  }
  fprintf(fp, "  ]\n}\n");
  fclose(fp);
}

// ── Kernel Descriptor Patching for Wave64 ────────────────────────────────────

static void PatchKernelDescriptorsForWave64(uint8_t* elf, size_t elf_size,
                                             const ElfInfo& info) {
  if (info.text_idx < 0) return;
  const uint8_t* text = elf + info.text_offset;

  // COv3 KD layout: RSRC3@44, RSRC1@48, RSRC2@52, props@56
  for (uint64_t offset = 0; offset + 64 <= info.text_size; offset += 256) {
    uint64_t entry_offset;
    std::memcpy(&entry_offset, text + offset + 16, 8);
    if (entry_offset != 256) continue;

    // Read RSRC1 from COv3 offset 48
    uint32_t rsrc1;
    std::memcpy(&rsrc1, text + offset + 48, 4);
    rsrc1 &= 0x00FFFFFFu;
    rsrc1 |= (1u << 21) | (1u << 23);

    uint32_t vgpr_field12 = rsrc1 & 0x3Fu;
    uint32_t sgpr_field12_kd = (rsrc1 >> 6) & 0x3Fu;
    uint32_t num_vgprs = (vgpr_field12 + 1u) * 12u;
    if (num_vgprs < 8u) num_vgprs = 8u;
    num_vgprs += 4u;
    uint32_t wmma_temp_max = 248u + 6u;
    if (wmma_temp_max > num_vgprs) num_vgprs = wmma_temp_max;
    uint32_t gfx9_vgpr = ((num_vgprs + 3u) / 4u) - 1u;
    if (gfx9_vgpr > 63u) gfx9_vgpr = 63u;
    rsrc1 &= ~0xFFFu;
    rsrc1 |= (gfx9_vgpr & 0x3Fu);
    {
      uint32_t num_sgprs = (sgpr_field12_kd + 1u) * 16u + 8u;
      const char* sgpr_key = ".sgpr_count";
      for (size_t i = 0; i + 12 < elf_size; i++) {
        if (std::memcmp(elf + i, sgpr_key, 11) == 0) {
          uint8_t val = elf[i + 11];
          uint32_t sc = (val <= 0x7F) ? val : (val == 0xCC ? elf[i+12] : 0);
          if (sc + 8 > num_sgprs) num_sgprs = sc + 8;
          break;
        }
      }
      uint32_t gfx9_sgpr = (num_sgprs / 8u) - 1u;
      if (gfx9_sgpr > 12u) gfx9_sgpr = 12u;
      rsrc1 |= (gfx9_sgpr << 6u);
    }
    // Write RSRC1 to COv3 offset 48
    std::memcpy(elf + info.text_offset + offset + 48, &rsrc1, 4);

    // Write RSRC2 at COv3 offset 52
    uint32_t rsrc2;
    std::memcpy(&rsrc2, text + offset + 52, 4);
    rsrc2 |= (1u << 7) | (1u << 8) | (1u << 9); // WG_ID X/Y/Z
    rsrc2 &= ~(1u << 10);                         // clear WG_INFO
    rsrc2 = (rsrc2 & ~(0x3u << 11)) | (1u << 11); // WORKITEM_ID=1 (X+Y)
    rsrc2 = (rsrc2 & ~(0x1Fu << 1)) | (2u << 1);  // USER_SGPR_COUNT=2
    std::memcpy(elf + info.text_offset + offset + 52, &rsrc2, 4);

    // Write kernel_code_properties at COv3 offset 56
    uint16_t props;
    std::memcpy(&props, text + offset + 56, 2);
    props = static_cast<uint16_t>(
        (static_cast<uint32_t>(props) & ~(1u << 10)) | (1u << 3));
    std::memcpy(elf + info.text_offset + offset + 56, &props, 2);

    // Write RSRC3 at COv3 offset 44
    uint32_t rsrc3 = gfx9_vgpr;
    std::memcpy(elf + info.text_offset + offset + 44, &rsrc3, 4);
  }
}

// ── ELF Metadata Patching ────────────────────────────────────────────────────

static void PatchElfMetadata(uint8_t* elf, size_t elf_size,
                              const std::string& target_cpu) {
  uint32_t e_flags;
  std::memcpy(&e_flags, elf + 48, 4);
  uint8_t target_mach = 0;
  if (target_cpu == "gfx950") target_mach = llvm::ELF::EF_AMDGPU_MACH_AMDGCN_GFX950;
  else if (target_cpu == "gfx942") target_mach = llvm::ELF::EF_AMDGPU_MACH_AMDGCN_GFX942;
  else if (target_cpu == "gfx90a") target_mach = llvm::ELF::EF_AMDGPU_MACH_AMDGCN_GFX90A;
  if (target_mach != 0) {
    // Replace arch ID and set sramecc/xnack bits to match target requirements.
    // Bits 8-9: xnack (00=unsupported, 01=any, 10=off, 11=on)
    // Bits 10-11: sramecc (00=unsupported, 01=any, 10=off, 11=on)
    // MI300X (gfx942) requires sramecc:on, xnack:off.
    e_flags = (e_flags & ~0xFFFu) | target_mach;
    if (target_cpu == "gfx942" || target_cpu == "gfx950") {
      e_flags |= (0x3 << 10) | (0x2 << 8);  // sramecc:on, xnack:off
    } else if (target_cpu == "gfx90a") {
      e_flags |= (0x3 << 10) | (0x2 << 8);  // sramecc:on, xnack:off
    }
    std::memcpy(elf + 48, &e_flags, 4);
  }

  std::string old_isa_full = "amdgcn-amd-amdhsa--gfx1250";
  std::string new_isa_full = "amdgcn-amd-amdhsa--" + target_cpu;
  for (size_t i = 0; i + old_isa_full.size() <= elf_size; ++i) {
    if (std::memcmp(elf + i, old_isa_full.data(), old_isa_full.size()) == 0) {
      if (new_isa_full.size() <= old_isa_full.size()) {
        // Also fix the msgpack string length byte preceding the data.
        // msgpack str8: 0xd9 <len>; fixstr: 0xa0|len (len<32)
        if (i >= 2 && elf[i - 2] == 0xd9 &&
            static_cast<uint8_t>(elf[i - 1]) == old_isa_full.size()) {
          elf[i - 1] = static_cast<uint8_t>(new_isa_full.size());
        } else if (i >= 1 &&
                   static_cast<uint8_t>(elf[i - 1]) == (0xa0 | old_isa_full.size())) {
          elf[i - 1] = 0xa0 | static_cast<uint8_t>(new_isa_full.size());
        }
        std::memcpy(elf + i, new_isa_full.data(), new_isa_full.size());
        for (size_t j = new_isa_full.size(); j < old_isa_full.size(); ++j)
          elf[i + j] = '\0';
      }
    }
  }

  for (size_t i = 0; i + 7 <= elf_size; ++i) {
    if (std::memcmp(elf + i, "gfx1250", 7) == 0) {
      if (target_cpu.size() <= 7) {
        std::memcpy(elf + i, target_cpu.c_str(), target_cpu.size());
        for (size_t j = target_cpu.size(); j < 7; ++j)
          elf[i + j] = '\0';
      }
    }
  }

  {
    const char* wf_key = ".wavefront_size";
    size_t wf_key_len = 15;
    for (size_t i = 0; i + wf_key_len + 1 <= elf_size; ++i) {
      if (std::memcmp(elf + i, wf_key, wf_key_len) == 0) {
        uint8_t val = elf[i + wf_key_len];
        if (val == 0x20) {
          elf[i + wf_key_len] = 0x40;
          HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: patched wavefront_size 32 → 64\n";
        }
      }
    }
  }

  // Patch .max_flat_workgroup_size: must be >= wavefront_size (64)
  {
    const char* wg_key = ".max_flat_workgroup_size";
    size_t wg_key_len = 24;
    for (size_t i = 0; i + wg_key_len + 1 <= elf_size; ++i) {
      if (std::memcmp(elf + i, wg_key, wg_key_len) == 0) {
        uint8_t val = elf[i + wg_key_len];
        if (val == 0x20) { // msgpack fixint 32
          elf[i + wg_key_len] = 0x40; // msgpack fixint 64
          HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: patched max_flat_workgroup_size 32 → 64\n";
        }
      }
    }
  }

  // Insert amdhsa.target if not present: replace top-level msgpack fixmap
  // count from 3 to 4 and repurpose custom.config space for amdhsa.target
  {
    // Find the msgpack desc start in the .note section
    const char* note_name = "AMDGPU";
    for (size_t i = 0; i + 12 <= elf_size; ++i) {
      if (std::memcmp(elf + i + 12, note_name, 6) == 0) {
        uint32_t namesz, descsz;
        std::memcpy(&namesz, elf + i, 4);
        std::memcpy(&descsz, elf + i + 4, 4);
        size_t name_aligned = (namesz + 3) & ~3;
        size_t desc_start = i + 12 + name_aligned;
        if (desc_start + descsz > elf_size) break;
        // Check if amdhsa.target already exists
        std::string tgt_str = "amdhsa.target";
        bool has_target = false;
        for (size_t j = desc_start; j + tgt_str.size() <= desc_start + descsz; ++j) {
          if (std::memcmp(elf + j, tgt_str.data(), tgt_str.size()) == 0) {
            has_target = true;
            break;
          }
        }
        if (!has_target) {
          // Build the target ISA string
          std::string isa = "amdgcn-amd-amdhsa--" + target_cpu;
          // We need to add a new map entry. Strategy:
          // 1. Remove custom.config entry to make space
          // 2. Increment map count
          // 3. Append amdhsa.target entry in freed space
          // For now, just increment the fixmap count if possible
          uint8_t map_byte = elf[desc_start];
          if ((map_byte & 0xF0) == 0x80) {
            // Find and remove "custom.config" key-value
            std::string cc_key = "custom.config";
            for (size_t j = desc_start; j + cc_key.size() + 1 <= desc_start + descsz; ++j) {
              if (std::memcmp(elf + j + 1, cc_key.data(), cc_key.size()) == 0 &&
                  elf[j] == (0xa0 | cc_key.size())) {
                // Found custom.config key at j. The key is fixstr(13) + 13 bytes.
                // We need to skip the value too (a small map).
                // Just overwrite with amdhsa.target key-value
                size_t pos = j;
                // Write key: fixstr(13) "amdhsa.target"
                elf[pos++] = 0xa0 | tgt_str.size();
                std::memcpy(elf + pos, tgt_str.data(), tgt_str.size());
                pos += tgt_str.size();
                // Write value: str8(isa)
                if (isa.size() < 32) {
                  elf[pos++] = 0xa0 | isa.size();
                } else {
                  elf[pos++] = 0xd9;
                  elf[pos++] = static_cast<uint8_t>(isa.size());
                }
                std::memcpy(elf + pos, isa.data(), isa.size());
                pos += isa.size();
                // Zero-fill remaining custom.config space
                size_t end = desc_start + descsz;
                while (pos < end) elf[pos++] = 0xc0; // msgpack nil
                HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: added amdhsa.target=" << isa << "\n";
                break;
              }
            }
          }
        }
        break;
      }
    }
  }

  // Fix kernel_code_entry_byte_offset in the KD: the source ELF may have the
  // kernel entry point at a non-zero offset within .text (due to prefix data),
  // but our reassembled .text starts with the kernel code at offset 0. Update
  // the KD to point to the start of the new .text section.
  {
    // Parse section headers to find .rodata and .text VMAs
    uint64_t e_shoff_kd;
    uint16_t e_shentsize_kd, e_shnum_kd, e_shstrndx_kd;
    std::memcpy(&e_shoff_kd, elf + 40, 8);
    std::memcpy(&e_shentsize_kd, elf + 58, 2);
    std::memcpy(&e_shnum_kd, elf + 60, 2);
    std::memcpy(&e_shstrndx_kd, elf + 62, 2);
    if (e_shoff_kd + (uint64_t)e_shnum_kd * e_shentsize_kd <= elf_size) {
      uint64_t shstr_off_kd;
      std::memcpy(&shstr_off_kd, elf + e_shoff_kd + (uint64_t)e_shstrndx_kd * e_shentsize_kd + 24, 8);
      uint64_t rodata_vma = 0, rodata_foff = 0, text_vma = 0;
      bool found_rodata = false, found_text = false;
      for (int s = 0; s < e_shnum_kd; ++s) {
        uint8_t* sh = elf + e_shoff_kd + (uint64_t)s * e_shentsize_kd;
        uint32_t name_idx; std::memcpy(&name_idx, sh, 4);
        const char* sname = (const char*)(elf + shstr_off_kd + name_idx);
        uint64_t sh_addr; std::memcpy(&sh_addr, sh + 16, 8);
        uint64_t sh_offset; std::memcpy(&sh_offset, sh + 24, 8);
        if (std::strcmp(sname, ".rodata") == 0) {
          rodata_vma = sh_addr; rodata_foff = sh_offset; found_rodata = true;
        } else if (std::strcmp(sname, ".text") == 0) {
          text_vma = sh_addr; found_text = true;
        }
      }
      if (found_rodata && found_text && rodata_foff + 24 <= elf_size) {
        // kernel_code_entry_byte_offset is at KD offset 16 (not 0!)
        // Offset 0 is group_segment_fixed_size — do NOT overwrite it.
        uint64_t old_entry;
        std::memcpy(&old_entry, elf + rodata_foff + 16, 8);
        uint64_t new_entry = text_vma - rodata_vma;
        if (old_entry != new_entry) {
          std::memcpy(elf + rodata_foff + 16, &new_entry, 8);
          HotswapLog(HotswapLogLevel::Info)
              << "hotswap: transpile: patched KD entry_byte_offset 0x"
              << std::hex << old_entry << " → 0x" << new_entry << "\n";
        }
      }
    }
  }

  // Fix overlapping ELF LOAD segments: the MC assembler sometimes creates
  // a RW LOAD segment whose vaddr range overlaps the RE (text) segment,
  // which causes a segfault in libhsa-runtime64 during hipModuleLoad.
  {
    uint64_t e_phoff;
    uint16_t e_phentsize, e_phnum;
    std::memcpy(&e_phoff, elf + 32, 8);
    std::memcpy(&e_phentsize, elf + 54, 2);
    std::memcpy(&e_phnum, elf + 56, 2);
    if (e_phoff + (uint64_t)e_phnum * e_phentsize <= elf_size) {
      // Find max end vaddr of all RE LOAD segments
      uint64_t re_end = 0;
      for (int i = 0; i < e_phnum; ++i) {
        uint8_t* ph = elf + e_phoff + (uint64_t)i * e_phentsize;
        uint32_t p_type; std::memcpy(&p_type, ph, 4);
        uint32_t p_flags; std::memcpy(&p_flags, ph + 4, 4);
        uint64_t p_vaddr; std::memcpy(&p_vaddr, ph + 16, 8);
        uint64_t p_memsz; std::memcpy(&p_memsz, ph + 40, 8);
        if (p_type == 1 /*PT_LOAD*/ && (p_flags & 1) /*PF_X*/) {
          uint64_t end = p_vaddr + p_memsz;
          if (end > re_end) re_end = end;
        }
      }
      // Fix any RW LOAD segments that overlap
      for (int i = 0; i < e_phnum; ++i) {
        uint8_t* ph = elf + e_phoff + (uint64_t)i * e_phentsize;
        uint32_t p_type; std::memcpy(&p_type, ph, 4);
        uint32_t p_flags; std::memcpy(&p_flags, ph + 4, 4);
        uint64_t p_vaddr; std::memcpy(&p_vaddr, ph + 16, 8);
        uint64_t p_filesz; std::memcpy(&p_filesz, ph + 32, 8);
        if (p_type == 1 /*PT_LOAD*/ && (p_flags & 2) /*PF_W*/ &&
            p_vaddr < re_end) {
          uint64_t new_vaddr = (re_end + 0xFFF) & ~0xFFFULL;
          uint64_t new_memsz = p_filesz +
              ((0x1000 - ((new_vaddr + p_filesz) & 0xFFF)) & 0xFFF);
          std::memcpy(ph + 16, &new_vaddr, 8); // p_vaddr
          std::memcpy(ph + 24, &new_vaddr, 8); // p_paddr
          std::memcpy(ph + 40, &new_memsz, 8); // p_memsz
          HotswapLog(HotswapLogLevel::Info)
              << "hotswap: transpile: fixed RW segment vaddr 0x" << std::hex
              << p_vaddr << " → 0x" << new_vaddr << "\n";
          // Also fix DYNAMIC and GNU_RELRO segments with same old vaddr
          for (int j = 0; j < e_phnum; ++j) {
            uint8_t* ph2 = elf + e_phoff + (uint64_t)j * e_phentsize;
            uint32_t t2; std::memcpy(&t2, ph2, 4);
            uint64_t v2; std::memcpy(&v2, ph2 + 16, 8);
            if (j != i && v2 == p_vaddr &&
                (t2 == 2 /*PT_DYNAMIC*/ || t2 == 0x6474e552 /*PT_GNU_RELRO*/)) {
              std::memcpy(ph2 + 16, &new_vaddr, 8);
              std::memcpy(ph2 + 24, &new_vaddr, 8);
              if (t2 == 0x6474e552)
                std::memcpy(ph2 + 40, &new_memsz, 8);
            }
          }
          // Fix section headers: .dynamic and .relro_padding
          uint64_t e_shoff2;
          uint16_t e_shentsize2, e_shnum2, e_shstrndx2;
          std::memcpy(&e_shoff2, elf + 40, 8);
          std::memcpy(&e_shentsize2, elf + 58, 2);
          std::memcpy(&e_shnum2, elf + 60, 2);
          std::memcpy(&e_shstrndx2, elf + 62, 2);
          uint64_t shstr_off2;
          std::memcpy(&shstr_off2, elf + e_shoff2 + (uint64_t)e_shstrndx2 * e_shentsize2 + 24, 8);
          for (int s = 0; s < e_shnum2; ++s) {
            uint8_t* sh = elf + e_shoff2 + (uint64_t)s * e_shentsize2;
            uint32_t name_idx; std::memcpy(&name_idx, sh, 4);
            uint64_t sh_addr; std::memcpy(&sh_addr, sh + 16, 8);
            const char* sname = (const char*)(elf + shstr_off2 + name_idx);
            if (sh_addr == p_vaddr) {
              std::memcpy(sh + 16, &new_vaddr, 8);
            } else if (std::strcmp(sname, ".relro_padding") == 0) {
              uint64_t ra = new_vaddr + p_filesz;
              uint64_t rs = new_memsz - p_filesz;
              std::memcpy(sh + 16, &ra, 8);
              std::memcpy(sh + 32, &rs, 8);
            }
          }
        }
      }
    }
  }
}

// ── Opcode-based MCInst-to-MCInst translation ────────────────────────────────

static bool TranslateViaOpcode(const llvm::MCInst &src_inst, unsigned src_opcode,
                                const OpcodeMapper &mapper, unsigned tgt_gen,
                                const llvm::MCInstrInfo &src_MCII,
                                const llvm::MCInstrInfo &tgt_MCII,
                                llvm::MCInst &out_inst) {
  unsigned pseudo = mapper.toPseudo(src_opcode);
  unsigned tgt_opcode = OpcodeMapper::toTarget(pseudo, tgt_gen);
  if (tgt_opcode == static_cast<unsigned>(-1))
    return false;

  // Validate opcode is within range — cross-family mapping can produce
  // bogus indices when the pseudo->real mapping doesn't exist for the
  // target generation.
  if (tgt_opcode >= tgt_MCII.getNumOpcodes())
    return false;

  const llvm::MCInstrDesc &tgt_desc = tgt_MCII.get(tgt_opcode);

  out_inst.setOpcode(tgt_opcode);

  unsigned num_ops = std::min(src_inst.getNumOperands(),
                               static_cast<unsigned>(tgt_desc.getNumOperands()));
  for (unsigned i = 0; i < num_ops; ++i)
    out_inst.addOperand(src_inst.getOperand(i));

  return true;
}

// ── Direct MCInst encoding ───────────────────────────────────────────────────

static std::vector<uint8_t> EncodeMCInst(const llvm::MCInst &inst,
                                          const LLVMState &state) {
  if (!state.CE) return {};
  llvm::SmallVector<char, 16> cb;
  llvm::SmallVector<llvm::MCFixup, 4> fixups;
  state.CE->encodeInstruction(inst, cb, fixups, *state.STI);
  return std::vector<uint8_t>(cb.begin(), cb.end());
}

// ── TranspileCodeObject ──────────────────────────────────────────────────────

amd_comgr_status_t
TranspileCodeObject(const void *elf_data, size_t elf_size,
                    const std::string &source_isa,
                    const std::string &target_isa,
                    void **out_data, size_t *out_size,
                    amd_comgr_hotswap_result_t *result) {
  TranspileStats stats;
  std::string src_cpu = ExtractCPU(source_isa);
  std::string tgt_cpu = ExtractCPU(target_isa);

  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: " << src_cpu << " → " << tgt_cpu << "\n";

  const uint8_t* elf = static_cast<const uint8_t*>(elf_data);
  size_t size = elf_size;

  ElfInfo elf_info;
  if (!ParseElfInfo(elf, size, elf_info)) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to parse ELF\n";
    return AMD_COMGR_STATUS_ERROR;
  }
  if (elf_info.text_size == 0) {
    HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: empty .text section\n";
    MallocBuffer copy(elf_size);
    if (!copy) return AMD_COMGR_STATUS_ERROR;
    std::memcpy(copy.data, elf_data, elf_size);
    *out_data = copy.release();
    *out_size = elf_size;
    return AMD_COMGR_STATUS_SUCCESS;
  }

  LLVMState src_state = InitLLVMCached(source_isa);
  if (!src_state.valid) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to init source ISA '" << source_isa << "'\n";
    return AMD_COMGR_STATUS_ERROR;
  }

  LLVMState tgt_state = InitLLVMCached(target_isa);
  if (!tgt_state.valid) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to init target ISA '" << target_isa << "'\n";
    return AMD_COMGR_STATUS_ERROR;
  }

  unsigned src_gen = GetEncodingFamily(src_cpu);
  unsigned tgt_gen = GetEncodingFamily(tgt_cpu);
  OpcodeMapper &mapper = GetOpcodeMapper(src_gen, *src_state.MCII);

  const uint8_t* text = elf + elf_info.text_offset;

  struct KernelInfo {
    uint64_t desc_offset;
    uint64_t code_offset;
    std::string name;
    uint32_t wg_x = 0; // workgroup size X from kernel name (_WGxx_yy_zz)
    uint32_t wg_y = 0; // workgroup size Y
  };
  std::vector<KernelInfo> kernels;
  for (uint64_t off = 0; off + 256 <= elf_info.text_size; off += 256) {
    uint64_t entry_offset;
    std::memcpy(&entry_offset, text + off + 16, 8);
    if (entry_offset == 256)
      kernels.push_back({off, off + 256, "", 0, 0});
  }

  if (kernels.empty()) {
    uint64_t code_offset_in_text = 0;
    uint64_t text_vaddr = 0;
    if (elf_info.text_idx >= 0)
      text_vaddr = elf_info.sections[elf_info.text_idx].addr;
    for (const auto& sec : elf_info.sections) {
      if (sec.name == ".rodata" && sec.size >= 64) {
        for (uint64_t off = 0; off + 64 <= sec.size; off += 64) {
          const uint8_t* desc = elf + sec.offset + off;
          uint64_t entry;
          std::memcpy(&entry, desc + 16, 8);
          if (entry > 0 && entry < 1000000) {
            uint64_t kd_vaddr = sec.addr + off;
            uint64_t code_vaddr = kd_vaddr + entry;
            if (code_vaddr >= text_vaddr)
              code_offset_in_text = code_vaddr - text_vaddr;
            break;
          }
        }
        break;
      }
    }
    HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: no embedded descriptors in .text, "
              << "code at .text internal offset " << code_offset_in_text << "\n";
    kernels.push_back({code_offset_in_text, code_offset_in_text, "", 0, 0});
  } else {
    HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: found " << kernels.size()
              << " embedded kernel descriptor(s)\n";
  }

  // Look up kernel names from ELF symbols and parse workgroup dimensions
  // from the _WGxx_yy_zz pattern in Tensile kernel names.
  for (auto& kern : kernels) {
    // Find the function symbol whose KD (.kd suffix) matches this descriptor offset
    uint64_t kd_vaddr = elf_info.text_addr + kern.desc_offset;
    for (const auto& sym : elf_info.symbols) {
      if (sym.value == kd_vaddr && sym.name.size() > 3 &&
          sym.name.substr(sym.name.size() - 3) == ".kd") {
        kern.name = sym.name.substr(0, sym.name.size() - 3);
        break;
      }
    }
    // Fallback: find function symbol at code_offset
    if (kern.name.empty()) {
      uint64_t code_vaddr = elf_info.text_addr + kern.code_offset;
      for (const auto& sym : elf_info.symbols) {
        uint8_t sym_type = sym.info & 0xf;
        if ((sym_type == 2 || sym_type == 10) && sym.value == code_vaddr) {
          kern.name = sym.name;
          break;
        }
      }
    }

    // Parse _WGxx_yy_zz from kernel name
    if (!kern.name.empty()) {
      size_t wg_pos = kern.name.find("_WG");
      if (wg_pos != std::string::npos) {
        // Format: _WG<X>_<Y>_<Z> where X,Y,Z are decimal numbers
        const char* p = kern.name.c_str() + wg_pos + 3;
        char* end = nullptr;
        unsigned long wx = std::strtoul(p, &end, 10);
        if (end && *end == '_') {
          p = end + 1;
          unsigned long wy = std::strtoul(p, &end, 10);
          kern.wg_x = static_cast<uint32_t>(wx);
          kern.wg_y = static_cast<uint32_t>(wy);
        }
      }
      HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: kernel '" << kern.name
                << "' WG_X=" << kern.wg_x << " WG_Y=" << kern.wg_y << "\n";
    }
  }

  std::string translated_asm;
  translated_asm += ".text\n";

  TranspileMapping mapping;
  mapping.source_isa = src_cpu;
  mapping.target_isa = tgt_cpu;
  // Count target instructions emitted (for offset resolution later)
  uint32_t tgt_instr_count = 0;

  for (size_t ki = 0; ki < kernels.size(); ++ki) {
    auto& kern = kernels[ki];

    uint64_t emit_end = kern.code_offset;
    uint64_t emit_start = (kern.desc_offset != kern.code_offset) ? kern.desc_offset : 0;
    for (uint64_t i = emit_start; i < emit_end; i += 4) {
      if (i + 4 > elf_info.text_size) break;
      uint32_t word;
      std::memcpy(&word, text + i, 4);
      std::ostringstream oss;
      oss << ".long 0x" << std::hex << word;
      translated_asm += oss.str() + "\n";
    }

    uint32_t num_vgprs12 = 8;
    uint32_t num_sgprs12 = 16;
    {
      // COv3 KD: RSRC1 is at offset 48 (RSRC3 is at offset 44)
      uint32_t rsrc1_src = 0;
      if (kern.desc_offset != kern.code_offset &&
          kern.desc_offset + 52 <= elf_info.text_size)
        std::memcpy(&rsrc1_src, text + kern.desc_offset + 48, 4);
      else {
        for (const auto& sec : elf_info.sections) {
          if (sec.name == ".rodata" && sec.size >= 64) {
            for (uint64_t off = 0; off + 64 <= sec.size; off += 64) {
              const uint8_t* desc = elf + sec.offset + off;
              uint64_t entry;
              std::memcpy(&entry, desc + 16, 8);
              if (entry > 0 && entry < 1000000) { std::memcpy(&rsrc1_src, desc + 48, 4); break; }
            }
            break;
          }
        }
      }
      if (rsrc1_src) {
        num_vgprs12 = ((rsrc1_src & 0x3Fu) + 1u) * 12u;
        num_sgprs12 = (((rsrc1_src >> 6) & 0x3Fu) + 1u) * 16u;
        HotswapLog(HotswapLogLevel::Debug) << "hotswap: transpile: GFX12 RSRC1=0x" << std::hex
                  << rsrc1_src << std::dec << " → num_vgprs12=" << num_vgprs12
                  << " num_sgprs12=" << num_sgprs12 << "\n";
      }
    }
    if (num_vgprs12 < 8u) num_vgprs12 = 8u;
    if (num_sgprs12 < 16u) num_sgprs12 = 16u;

    if (num_vgprs12 > 256u) {
      HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: kernel " << ki
                << " uses " << num_vgprs12 << " VGPRs (wave32), exceeds 256 "
                << "VGPR limit for wave64 target — cannot transpile\n";
      return AMD_COMGR_STATUS_ERROR;
    }

    // Scan MSGPACK for .sgpr_count
    {
      const char* key = ".sgpr_count";
      size_t key_len = 11;
      for (const auto& sec : elf_info.sections) {
        if (sec.name == ".note" && sec.size > key_len + 2) {
          for (size_t i = 0; i + key_len + 1 < sec.size; i++) {
            if (std::memcmp(elf + sec.offset + i, key, key_len) == 0) {
              uint8_t val = elf[sec.offset + i + key_len];
              uint32_t sgpr_count = 0;
              if (val <= 0x7F) sgpr_count = val;
              else if (val == 0xCC) sgpr_count = elf[sec.offset + i + key_len + 1];
              else if (val == 0xCD) {
                uint16_t v16;
                std::memcpy(&v16, elf + sec.offset + i + key_len + 1, 2);
                sgpr_count = (v16 >> 8) | ((v16 & 0xFF) << 8);
              }
              if (sgpr_count > num_sgprs12) num_sgprs12 = sgpr_count;
              break;
            }
          }
          break;
        }
      }
    }

    // Scan MSGPACK for .vgpr_count (authoritative, overrides RSRC1 estimate)
    {
      const char* key = ".vgpr_count";
      size_t key_len = 11;
      for (const auto& sec : elf_info.sections) {
        if (sec.name == ".note" && sec.size > key_len + 2) {
          for (size_t i = 0; i + key_len + 1 < sec.size; i++) {
            if (std::memcmp(elf + sec.offset + i, key, key_len) == 0) {
              uint8_t val = elf[sec.offset + i + key_len];
              uint32_t vgpr_count = 0;
              if (val <= 0x7F) vgpr_count = val;
              else if (val == 0xCC) vgpr_count = elf[sec.offset + i + key_len + 1];
              else if (val == 0xCD) {
                uint16_t v16;
                std::memcpy(&v16, elf + sec.offset + i + key_len + 1, 2);
                vgpr_count = (v16 >> 8) | ((v16 & 0xFF) << 8);
              }
              if (vgpr_count > num_vgprs12) {
                HotswapLog(HotswapLogLevel::Info)
                    << "hotswap: transpile: .vgpr_count=" << vgpr_count
                    << " overrides RSRC1 estimate of " << num_vgprs12 << "\n";
                num_vgprs12 = vgpr_count;
              }
              break;
            }
          }
          break;
        }
      }
    }

    uint32_t save_vgpr_x = num_vgprs12;
    uint32_t save_vgpr_y = num_vgprs12 + 1u;
    // Temp SGPRs for exec save/restore in WMMA→MFMA expansion.
    // On gfx942, max addressable SGPR is s101. Need 2 consecutive SGPRs.
    // TODO(gfx950): verify max addressable SGPR limit
    uint32_t cmpx_temp_sgpr = num_sgprs12;
    if (cmpx_temp_sgpr > 100u) cmpx_temp_sgpr = 100u;
    const std::string sv_x = "v" + std::to_string(save_vgpr_x);
    const std::string sv_y = "v" + std::to_string(save_vgpr_y);

    uint64_t code_end = elf_info.text_size;
    if (ki + 1 < kernels.size())
      code_end = kernels[ki + 1].desc_offset;

    struct SourceInstr {
      std::string text;
      uint64_t pc_offset;
      uint32_t size;
      llvm::MCInst inst;
      bool valid_inst;
    };
    std::vector<SourceInstr> source_instrs;
    std::vector<std::string> source_lines;
    uint64_t pos = kern.code_offset;
    while (pos < code_end) {
      llvm::MCInst inst;
      uint64_t inst_size = 0;
      llvm::ArrayRef<uint8_t> bytes(text + pos, code_end - pos);
      auto status = src_state.disasm->getInstruction(inst, inst_size, bytes, pos, llvm::nulls());
      if (status == llvm::MCDisassembler::Fail) {
        if (pos + 4 <= code_end) {
          uint32_t word;
          std::memcpy(&word, text + pos, 4);
          std::ostringstream oss;
          oss << ".long 0x" << std::hex << word;
          source_instrs.push_back({oss.str(), pos, 4, llvm::MCInst(), false});
          source_lines.push_back(oss.str());
        }
        pos += 4;
        ++stats.total_instructions;
        continue;
      }
      std::string asm_text;
      if (src_state.printer) {
        llvm::raw_string_ostream rso(asm_text);
        src_state.printer->printInst(&inst, 0, "", *src_state.STI, rso);
        rso.flush();
      }
      size_t start = asm_text.find_first_not_of(" \t");
      if (start != std::string::npos && start > 0)
        asm_text = asm_text.substr(start);
      if (!asm_text.empty()) {
        source_instrs.push_back({asm_text, pos, static_cast<uint32_t>(inst_size), inst, true});
        source_lines.push_back(asm_text);
      }
      pos += inst_size;
      ++stats.total_instructions;
    }

    HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: kernel " << ki << ": disassembled "
              << source_lines.size() << " instructions\n";

    // Branch label resolution
    std::map<uint64_t, std::string> branch_labels;
    int label_counter = 0;
    for (size_t i = 0; i < source_instrs.size(); ++i) {
      auto& info = source_instrs[i];
      std::string m = TranspileExtractMnemonic(info.text);
      bool is_branch = (m.find("s_branch") == 0 || m.find("s_cbranch_") == 0);
      if (!is_branch) continue;
      std::string ops = info.text.substr(info.text.find(m) + m.size());
      size_t s = ops.find_first_not_of(" \t");
      if (s == std::string::npos) continue;
      std::string offset_str = ops.substr(s);
      if (offset_str.find(".L_") == 0) continue;
      {
        int64_t raw = 0;
        const char *fc_begin = offset_str.data();
        const char *fc_end = offset_str.data() + offset_str.size();
        int fc_base = 10;
        if (offset_str.size() > 2 && offset_str[0] == '0' &&
            (offset_str[1] == 'x' || offset_str[1] == 'X')) {
          fc_begin += 2;
          fc_base = 16;
        }
        auto [fc_p, fc_ec] = std::from_chars(fc_begin, fc_end, raw, fc_base);
        if (fc_ec == std::errc()) {
          int64_t simm16 = static_cast<int16_t>(raw & 0xFFFF);
          uint64_t target_pc = info.pc_offset + 4 + simm16 * 4;
          uint64_t snapped_pc = target_pc;
          bool found = false;
          for (const auto& si : source_instrs) {
            if (si.pc_offset >= target_pc) { snapped_pc = si.pc_offset; found = true; break; }
          }
          if (!found && !source_instrs.empty())
            snapped_pc = source_instrs.back().pc_offset;
          if (branch_labels.find(snapped_pc) == branch_labels.end())
            branch_labels[snapped_pc] = ".L_br" + std::to_string(label_counter++);
        }
      }
    }

    // PC-relative computed jump resolution (s_getpc + s_add_i32 pattern)
    // Detect s_get_pc_i64 / s_getpc_b64 followed by s_add_co_i32 sN, OFFSET, 4
    // and create labels at the computed targets so they survive code expansion.
    // getpc_fixups maps source instruction index of the s_add_co_i32 to {target_label, dest_reg, addr_lo, addr_hi}
    struct GetpcFixup {
      std::string target_label;
      std::string dest_reg;     // sM in "s_add_co_i32 sM, ..."
      std::string addr_lo;      // sN in "s_add_co_u32 sN, sN, sM"
      std::string addr_hi;      // sN+1
      size_t addu32_idx;        // index of the s_add_co_u32 instruction
      size_t addci_idx;         // index of the s_add_co_ci_u32 instruction
    };
    std::map<size_t, GetpcFixup> getpc_fixups;
    for (size_t i = 0; i + 3 < source_instrs.size(); ++i) {
      std::string m = TranspileExtractMnemonic(source_instrs[i].text);
      if (m != "s_get_pc_i64" && m != "s_getpc_b64") continue;
      // Next instruction should be s_add_co_i32 sM, 0xHHHH, 4
      std::string m1 = TranspileExtractMnemonic(source_instrs[i+1].text);
      if (m1 != "s_add_co_i32" && m1 != "s_add_i32") continue;
      const auto& add_text = source_instrs[i+1].text;
      // Parse: s_add_co_i32 sM, 0xHHHH, 4
      // Extract the hex offset
      size_t hex_pos = add_text.find("0x");
      if (hex_pos == std::string::npos) continue;
      std::string hex_str = add_text.substr(hex_pos + 2);
      size_t hex_end = hex_str.find_first_not_of("0123456789abcdefABCDEF");
      if (hex_end != std::string::npos) hex_str = hex_str.substr(0, hex_end);
      uint64_t offset_val = 0;
      auto [p, ec] = std::from_chars(hex_str.data(), hex_str.data() + hex_str.size(), offset_val, 16);
      if (ec != std::errc()) continue;
      // Verify the ", 4" at the end
      if (add_text.find(", 4") == std::string::npos) continue;
      // Compute target: getpc returns addr of NEXT instr, then add (offset + 4)
      uint64_t getpc_next = source_instrs[i].pc_offset + 4; // s_get_pc_i64 is 4 bytes
      uint64_t target_pc = getpc_next + offset_val + 4;
      // Snap to nearest instruction boundary
      uint64_t snapped_pc = target_pc;
      bool found = false;
      for (const auto& si : source_instrs) {
        if (si.pc_offset >= target_pc) { snapped_pc = si.pc_offset; found = true; break; }
      }
      if (!found && !source_instrs.empty())
        snapped_pc = source_instrs.back().pc_offset;
      // Create label at target
      if (branch_labels.find(snapped_pc) == branch_labels.end())
        branch_labels[snapped_pc] = ".L_br" + std::to_string(label_counter++);
      // Parse the dest register from s_add_co_i32 sM, ...
      size_t dest_start = add_text.find_first_not_of(" \t", add_text.find(m1) + m1.size());
      std::string dest_reg;
      if (dest_start != std::string::npos) {
        size_t dest_end = add_text.find(',', dest_start);
        if (dest_end != std::string::npos)
          dest_reg = add_text.substr(dest_start, dest_end - dest_start);
      }
      // Parse addr_lo and addr_hi from the s_get_pc_i64 operand (e.g. "s[12:13]" -> s12, s13)
      const auto& getpc_text = source_instrs[i].text;
      std::string addr_lo, addr_hi;
      size_t bracket = getpc_text.find("s[");
      if (bracket != std::string::npos) {
        size_t num_start = bracket + 2;
        size_t colon = getpc_text.find(':', num_start);
        size_t rbracket = getpc_text.find(']', num_start);
        if (colon != std::string::npos && rbracket != std::string::npos) {
          addr_lo = "s" + getpc_text.substr(num_start, colon - num_start);
          addr_hi = "s" + getpc_text.substr(colon + 1, rbracket - colon - 1);
        }
      }
      GetpcFixup fixup;
      fixup.target_label = branch_labels[snapped_pc];
      fixup.dest_reg = dest_reg;
      fixup.addr_lo = addr_lo;
      fixup.addr_hi = addr_hi;
      fixup.addu32_idx = i + 2;
      fixup.addci_idx = i + 3;
      getpc_fixups[i + 1] = fixup; // key is index of the s_add_co_i32 instruction
      HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: getpc fixup: src_offset=0x"
          << std::hex << source_instrs[i].pc_offset << " offset=0x" << offset_val
          << " -> target=0x" << snapped_pc << " label=" << fixup.target_label << "\n";
    }

    // GFX12 45-bit NUM_RECORDS SRD encoding elimination
    // GFX12 splits NUM_RECORDS across word1[31:25] (low 7 bits) and word2 (upper >>7).
    // GFX9 uses a full 32-bit NUM_RECORDS in word2 only. Detect and eliminate the
    // 5-instruction encoding pattern so SRDs work correctly on GFX9.
    // Pattern:
    //   [i+0] s_and_b32 sTMP, sNR, 0x7f
    //   [i+1] s_lshl_b32 sTMP, sTMP, 25
    //   [i+2] s_and_b32 sW1, sW1, 0x1ffffff
    //   [i+3] s_or_b32 sW1, sW1, sTMP
    //   [i+4] s_lshr_b32 sNR, sNR, 7
    std::set<size_t> srd_encoding_nops;
    for (size_t i = 0; i + 4 < source_instrs.size(); ++i) {
      if (!source_instrs[i].valid_inst) continue;
      std::string m0 = TranspileExtractMnemonic(source_instrs[i].text);
      if (m0 != "s_and_b32") continue;
      // Check for ", 0x7f" or ", 127" at end of instruction
      const auto& t0 = source_instrs[i].text;
      if (t0.find("0x7f") == std::string::npos &&
          t0.find("0x7F") == std::string::npos) continue;
      // Verify [i+1]: s_lshl_b32 sTMP, sTMP, 25
      if (!source_instrs[i+1].valid_inst) continue;
      std::string m1 = TranspileExtractMnemonic(source_instrs[i+1].text);
      if (m1 != "s_lshl_b32") continue;
      const auto& t1 = source_instrs[i+1].text;
      if (t1.find(", 25") == std::string::npos) continue;
      // Verify [i+2]: s_and_b32 sW1, sW1, 0x1ffffff
      if (!source_instrs[i+2].valid_inst) continue;
      std::string m2 = TranspileExtractMnemonic(source_instrs[i+2].text);
      if (m2 != "s_and_b32") continue;
      const auto& t2 = source_instrs[i+2].text;
      if (t2.find("0x1ffffff") == std::string::npos &&
          t2.find("0x1FFFFFF") == std::string::npos) continue;
      // Verify [i+3]: s_or_b32
      if (!source_instrs[i+3].valid_inst) continue;
      std::string m3 = TranspileExtractMnemonic(source_instrs[i+3].text);
      if (m3 != "s_or_b32") continue;
      // Verify [i+4]: s_lshr_b32 sNR, sNR, 7
      if (!source_instrs[i+4].valid_inst) continue;
      std::string m4 = TranspileExtractMnemonic(source_instrs[i+4].text);
      if (m4 != "s_lshr_b32") continue;
      const auto& t4 = source_instrs[i+4].text;
      if (t4.find(", 7") == std::string::npos) continue;
      // Mark all 5 instructions for elimination
      for (size_t j = 0; j < 5; ++j)
        srd_encoding_nops.insert(i + j);
      HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: SRD 45-bit NUM_RECORDS encoding "
          << "eliminated at src_offset=0x" << std::hex << source_instrs[i].pc_offset
          << " (5 instructions)\n";
      i += 4; // skip past matched pattern
    }

    // GFX12→GFX9 SRD word3 fixup: GFX12 uses word3=0 for raw MUBUF access, but
    // GFX9 requires DATA_FORMAT!=0 (DATA_FORMAT=0 is BUF_DATA_FORMAT_INVALID and
    // silently drops buffer operations). Fix by replacing word3=0 with 0x00020000
    // (DATA_FORMAT=4=BUF_DATA_FORMAT_32).
    // Detect pattern: "s_mov_b32 sN, 0" where sN is word3 of an SRD.
    // Indicators: preceded by "s_mov_b32 s(N-1), 0x80000000" (num_records = 2GB).
    std::map<size_t, std::string> srd_word3_fixups;
    for (size_t i = 0; i + 1 < source_instrs.size(); ++i) {
      if (!source_instrs[i].valid_inst || !source_instrs[i+1].valid_inst) continue;
      const auto& t0 = source_instrs[i].text;
      const auto& t1 = source_instrs[i+1].text;
      // Match: s_mov_b32 sN, 0x80000000 followed by s_mov_b32 s(N+1), 0
      if (t0.find("s_mov_b32") == std::string::npos || t0.find("0x80000000") == std::string::npos)
        continue;
      if (t1.find("s_mov_b32") == std::string::npos) continue;
      // Extract register number from first instruction
      size_t s_pos = t0.find('s', t0.find("s_mov_b32") + 9);
      if (s_pos == std::string::npos) continue;
      size_t num_start = s_pos + 1;
      size_t num_end = t0.find_first_not_of("0123456789", num_start);
      if (num_start == num_end) continue;
      int reg_n = std::atoi(t0.substr(num_start, num_end - num_start).c_str());
      // Check second instruction has s(N+1) and ", 0" at end
      std::string expected_reg = "s" + std::to_string(reg_n + 1);
      if (t1.find(expected_reg) == std::string::npos) continue;
      // Verify it's ", 0" (not ", 0x...")
      size_t comma = t1.rfind(',');
      if (comma == std::string::npos) continue;
      std::string val = t1.substr(comma + 1);
      // Trim whitespace
      size_t vs = val.find_first_not_of(" \t");
      if (vs != std::string::npos) val = val.substr(vs);
      size_t ve = val.find_last_not_of(" \t\n\r");
      if (ve != std::string::npos) val = val.substr(0, ve + 1);
      if (val != "0") continue;
      // Replace this instruction
      srd_word3_fixups[i + 1] = "s_mov_b32 " + expected_reg + ", 0x00020000 ; GFX9 DATA_FORMAT=BUF_DATA_FORMAT_32";
      HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: SRD word3 fixup at src_offset=0x"
          << std::hex << source_instrs[i+1].pc_offset << " (" << expected_reg << " = 0 -> 0x00020000)\n";
    }
    // Also handle the conditional pattern where s_mov_b32 sN, 0 appears as
    // word3 initialization independent of the 0x80000000 word2 pattern
    // (e.g., bias/E SRDs: s_mov_b32 s35, 0 / s_mov_b32 s43, 0)
    // Require that nearby instructions (within a window) write to other
    // components of the same SRD (s(N-3), s(N-2), or s(N-1)), confirming
    // this is actually SRD setup and not a coincidental register reuse.
    for (size_t i = 0; i < source_instrs.size(); ++i) {
      if (!source_instrs[i].valid_inst) continue;
      if (srd_word3_fixups.count(i)) continue; // already handled
      const auto& t = source_instrs[i].text;
      if (t.find("s_mov_b32") == std::string::npos) continue;
      // Look for s_mov_b32 sN, 0 where sN is word3 of an SRD that's used with buffer ops
      size_t s_pos = t.find('s', t.find("s_mov_b32") + 9);
      if (s_pos == std::string::npos) continue;
      size_t num_start = s_pos + 1;
      size_t num_end = t.find_first_not_of("0123456789", num_start);
      if (num_start == num_end) continue;
      int reg_n = std::atoi(t.substr(num_start, num_end - num_start).c_str());
      // Check if it's ", 0"
      size_t comma = t.rfind(',');
      if (comma == std::string::npos) continue;
      std::string val = t.substr(comma + 1);
      size_t vs = val.find_first_not_of(" \t");
      if (vs != std::string::npos) val = val.substr(vs);
      size_t ve = val.find_last_not_of(" \t\n\r");
      if (ve != std::string::npos) val = val.substr(0, ve + 1);
      if (val != "0") continue;
      // Check if s[reg_n-3:reg_n] is used as a buffer SRD anywhere in the kernel
      int base_reg = reg_n - 3;
      if (base_reg < 0) continue;
      std::string srd_pattern = "s[" + std::to_string(base_reg) + ":" + std::to_string(reg_n) + "]";
      bool found_buffer_use = false;
      for (size_t j = 0; j < source_instrs.size(); ++j) {
        if (source_instrs[j].text.find(srd_pattern) != std::string::npos &&
            (source_instrs[j].text.find("buffer_") != std::string::npos)) {
          found_buffer_use = true;
          break;
        }
      }
      if (!found_buffer_use) continue;
      // Additional check: verify this is actually SRD setup by requiring that
      // nearby instructions (within a window of 10 before) write to another
      // component of the same SRD quad (s(N-3), s(N-2), or s(N-1)).
      // This prevents false positives where the register is reused for a
      // non-SRD purpose (e.g., as a tile counter) but the same register
      // quad happens to be used as an SRD elsewhere in the kernel.
      // Require writes to BOTH s(N-3) (base_lo) and s(N-2) (base_hi) within
      // a small window, confirming this is a 4-register SRD setup.
      bool found_base_lo = false, found_base_hi = false;
      constexpr size_t kSrdNeighborWindow = 10;
      size_t window_start = (i > kSrdNeighborWindow) ? i - kSrdNeighborWindow : 0;
      std::string reg_lo = "s" + std::to_string(reg_n - 3);
      std::string reg_hi = "s" + std::to_string(reg_n - 2);
      auto writes_to = [](const std::string& inst, const std::string& reg) {
        // Match any scalar instruction that writes to reg as destination
        // Covers: s_mov_b32, s_add_u32, s_add_co_u32, s_addc_u32,
        //         s_add_co_ci_u32, s_sub_u32, s_and_b32, s_or_b32, etc.
        std::string pat1 = reg + ",";
        std::string pat2 = reg + " ";
        // Find the register after the mnemonic (first space after start)
        size_t sp = inst.find(' ');
        if (sp == std::string::npos) return false;
        std::string after_mnemonic = inst.substr(sp + 1);
        return after_mnemonic.find(pat1) == 0 || after_mnemonic.find(pat2) == 0;
      };
      for (size_t j = window_start; j < i; ++j) {
        if (!source_instrs[j].valid_inst) continue;
        const auto& nt = source_instrs[j].text;
        if (writes_to(nt, reg_lo)) found_base_lo = true;
        if (writes_to(nt, reg_hi)) found_base_hi = true;
        // Also check s_mov_b64 s[N-3:N-2] which writes both at once
        std::string pair = "s[" + std::to_string(reg_n - 3) + ":" + std::to_string(reg_n - 2) + "]";
        if (writes_to(nt, pair)) { found_base_lo = true; found_base_hi = true; }
      }
      if (!found_base_lo || !found_base_hi) continue;
      std::string expected_reg = "s" + std::to_string(reg_n);
      srd_word3_fixups[i] = "s_mov_b32 " + expected_reg + ", 0x00020000 ; GFX9 DATA_FORMAT=BUF_DATA_FORMAT_32";
      HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: SRD word3 fixup (buffer-use heuristic) at src_offset=0x"
          << std::hex << source_instrs[i].pc_offset << " (" << expected_reg << " = 0 -> 0x00020000)\n";
    }

    // TTMP taint analysis
    std::vector<SourceInstrForTaint> taint_input;
    taint_input.reserve(source_instrs.size());
    for (const auto& si : source_instrs)
      taint_input.push_back({si.text, si.inst, si.valid_inst});
    auto taint_results = AnalyzeTTMPTaint(taint_input, *src_state.MCII, *src_state.MRI);

    for (auto& tr : taint_results) {
      if (tr.action == TaintAction::Replace) {
        if (tr.replace_src == "v5") tr.replace_src = sv_x;
        else if (tr.replace_src == "v4") tr.replace_src = sv_y;
      }
    }

    // With USER_SGPR_COUNT=2 and ENABLE_SGPR_KERNARG_SEGMENT_PTR=1,
    // s[0:1]=kernarg ptr (user SGPRs), system SGPRs start at s2.
    translated_asm += "v_mov_b32_e32 " + sv_x + ", s2 ; save workgroup_id_x\n";
    translated_asm += "v_mov_b32_e32 " + sv_y + ", s3 ; save workgroup_id_y\n";
    tgt_instr_count += 2;

    // gfx942 has FeaturePackedTID: with WORKITEM_ID=1, v0 = X | (Y << 10).
    // The source gfx1250 kernel expects v0 = flat_thread_id = Y * WG_X + X.
    // Unpack v0 and compute flat_id in the preamble.
    if (kern.wg_y > 1 && kern.wg_x > 0) {
      // Use a temp VGPR above the save registers
      std::string v_tmp = "v" + std::to_string(save_vgpr_y + 1u);
      translated_asm += "v_bfe_u32 " + v_tmp + ", v0, 10, 10"
                        " ; unpack Y = (v0 >> 10) & 0x3FF\n";
      translated_asm += "v_and_b32_e32 v0, 0x3ff, v0"
                        " ; unpack X = v0 & 0x3FF\n";
      translated_asm += "v_mad_u32_u24 v0, " + v_tmp + ", "
                        + std::to_string(kern.wg_x) + ", v0"
                        " ; flat_id = Y * WG_X + X\n";
      tgt_instr_count += 3;
      HotswapLog(HotswapLogLevel::Info)
          << "hotswap: transpile: emitted packed TID unpack preamble"
          << " (WG_X=" << kern.wg_x << ", WG_Y=" << kern.wg_y
          << ", tmp=" << v_tmp << ")\n";
    } else if (kern.wg_y <= 1 && kern.wg_x > 0) {
      // 1D workgroup: v0 already has just X (Y=0), no unpack needed
      HotswapLog(HotswapLogLevel::Debug)
          << "hotswap: transpile: 1D workgroup (WG_X=" << kern.wg_x
          << "), no packed TID unpack needed\n";
    } else {
      // Unknown WG dims: emit a conservative unpack that masks X from v0
      // This handles the case where we couldn't parse the kernel name
      translated_asm += "v_and_b32_e32 v0, 0x3ff, v0"
                        " ; mask packed TID to X only (WG dims unknown)\n";
      tgt_instr_count += 1;
      HotswapLog(HotswapLogLevel::Info)
          << "hotswap: transpile: unknown WG dims, masking v0 to X only\n";
    }

    mapping.kernel = "kernel_" + std::to_string(ki);

    std::vector<std::pair<std::string, std::string>> replace_regs;
    for (auto& tr : taint_results) {
      if (tr.action == TaintAction::Replace && !tr.replace_dst.empty())
        replace_regs.emplace_back(tr.replace_dst, tr.replace_src);
    }

    int early_exit_after = 0;
    if (const char* ee = std::getenv("HSA_HOTSWAP_EARLY_EXIT"))
      early_exit_after = std::atoi(ee);
    int emitted_count = 0;
    bool early_exit_done = false;

    for (size_t ii = 0; ii < source_lines.size(); ++ii) {
      const auto& line = source_lines[ii];

      if (ii < source_instrs.size()) {
        auto lbl = branch_labels.find(source_instrs[ii].pc_offset);
        if (lbl != branch_labels.end())
          translated_asm += lbl->second + ":\n";
      }

      if (ii < taint_results.size()) {
        if (taint_results[ii].action == TaintAction::Skip) {
          if (ii < source_instrs.size()) {
            std::string m = TranspileExtractMnemonic(source_instrs[ii].text);
            mapping.entries.push_back({source_instrs[ii].pc_offset, m,
                                       source_instrs[ii].size, "eliminated", 0, {}});
          }
          continue;
        }
        if (taint_results[ii].action == TaintAction::Replace) {
          auto& tr = taint_results[ii];
          translated_asm += "v_readfirstlane_b32 " + tr.replace_dst + ", " + tr.replace_src + "\n";
          if (ii < source_instrs.size()) {
            std::string m = TranspileExtractMnemonic(source_instrs[ii].text);
            mapping.entries.push_back({source_instrs[ii].pc_offset, m,
                                       source_instrs[ii].size, "replaced", 1, {}});
            ++tgt_instr_count;
          }
          continue;
        }
      }

      // GFX12 45-bit NUM_RECORDS SRD encoding elimination
      if (srd_encoding_nops.count(ii)) {
        if (ii < source_instrs.size()) {
          std::string m = TranspileExtractMnemonic(source_instrs[ii].text);
          mapping.entries.push_back({source_instrs[ii].pc_offset, m,
                                     source_instrs[ii].size, "srd_encoding_eliminated", 0, {}});
        }
        continue;
      }

      // GFX12→GFX9 SRD word3 fixup: replace word3=0 with valid DATA_FORMAT
      {
        auto w3_it = srd_word3_fixups.find(ii);
        if (w3_it != srd_word3_fixups.end()) {
          translated_asm += w3_it->second + "\n";
          if (ii < source_instrs.size()) {
            std::string m = TranspileExtractMnemonic(source_instrs[ii].text);
            mapping.entries.push_back({source_instrs[ii].pc_offset, m,
                                       source_instrs[ii].size, "srd_word3_fixup", 1, {}});
            ++tgt_instr_count;
          }
          ++emitted_count;
          continue;
        }
      }

      // PC-relative computed jump fixup: replace s_add_co_i32 + s_add_co_u32 + s_add_co_ci_u32
      // with label-relative addressing to handle code size changes from transpilation.
      {
        auto fixup_it = getpc_fixups.find(ii);
        if (fixup_it != getpc_fixups.end()) {
          auto& fx = fixup_it->second;
          // The previous instruction (s_getpc_b64) was already emitted.
          // Emit a local label right after it, then use label arithmetic.
          std::string here_label = ".L_getpc_" + std::to_string(ki) + "_" + std::to_string(ii);
          translated_asm += here_label + ":\n";
          // Replace the 3-instruction sequence:
          //   s_add_i32 sM, OFFSET, 4       -> (eliminated, folded into s_add_u32)
          //   s_add_u32 sN, sN, sM          -> s_add_u32 sN, sN, (target - here_label)@lo
          //   s_addc_u32 sN+1, sN+1, 0      -> s_addc_u32 sN+1, sN+1, (target - here_label)@hi
          translated_asm += "s_add_u32 " + fx.addr_lo + ", " + fx.addr_lo + ", " +
                            fx.target_label + " - " + here_label + "\n";
          translated_asm += "s_addc_u32 " + fx.addr_hi + ", " + fx.addr_hi + ", 0\n";
          // Record mapping for the 3 consumed instructions
          if (ii < source_instrs.size()) {
            std::string m = TranspileExtractMnemonic(source_instrs[ii].text);
            mapping.entries.push_back({source_instrs[ii].pc_offset, m,
                                       source_instrs[ii].size, "getpc_fixup", 0, {}});
          }
          if (fx.addu32_idx < source_instrs.size()) {
            std::string m = TranspileExtractMnemonic(source_instrs[fx.addu32_idx].text);
            mapping.entries.push_back({source_instrs[fx.addu32_idx].pc_offset, m,
                                       source_instrs[fx.addu32_idx].size, "getpc_fixup", 1, {}});
          }
          if (fx.addci_idx < source_instrs.size()) {
            std::string m = TranspileExtractMnemonic(source_instrs[fx.addci_idx].text);
            mapping.entries.push_back({source_instrs[fx.addci_idx].pc_offset, m,
                                       source_instrs[fx.addci_idx].size, "getpc_fixup", 1, {}});
          }
          tgt_instr_count += 2; // s_add_u32 + s_addc_u32
          ++emitted_count;
          // Skip the next 2 instructions (s_add_co_u32 and s_add_co_ci_u32)
          // but emit any labels that point to them
          for (size_t skip = 1; skip <= 2; ++skip) {
            size_t skip_idx = ii + skip;
            if (skip_idx < source_instrs.size()) {
              auto lbl = branch_labels.find(source_instrs[skip_idx].pc_offset);
              if (lbl != branch_labels.end())
                translated_asm += lbl->second + ":\n";
            }
          }
          ii += 2;
          continue;
        }
      }

      // Phase 5: try opcode-based direct translation for non-control-flow
      if (ii < source_instrs.size() && source_instrs[ii].valid_inst) {
        const auto &si = source_instrs[ii];
        unsigned src_opc = si.inst.getOpcode();
        const llvm::MCInstrDesc &src_desc = src_state.MCII->get(src_opc);
        if (!src_desc.isBranch() && !src_desc.isCall() &&
            !src_desc.isTerminator() && !src_desc.isReturn()) {
          llvm::MCInst tgt_inst;
          if (TranslateViaOpcode(si.inst, src_opc, mapper, tgt_gen,
                                  *src_state.MCII, *tgt_state.MCII, tgt_inst)) {
            auto encoded = EncodeMCInst(tgt_inst, tgt_state);
            if (!encoded.empty()) {
              uint32_t enc_count = 0;
              for (size_t b = 0; b + 4 <= encoded.size(); b += 4) {
                uint32_t word;
                std::memcpy(&word, encoded.data() + b, 4);
                std::ostringstream oss;
                oss << ".long 0x" << std::hex << word;
                translated_asm += oss.str() + "\n";
                ++enc_count;
              }
              stats.translated_renamed++;
              ++emitted_count;
              {
                std::string m = TranspileExtractMnemonic(si.text);
                mapping.entries.push_back({si.pc_offset, m, si.size, "renamed", enc_count, {}});
                tgt_instr_count += enc_count;
              }
              continue;
            }
          }
        }
      }

      // Fall through to existing text-based translation (with opcode hint)
      unsigned src_opc = ~0u;
      const llvm::MCInstrInfo *src_mcii = nullptr;
      if (ii < source_instrs.size() && source_instrs[ii].valid_inst) {
        src_opc = source_instrs[ii].inst.getOpcode();
        src_mcii = src_state.MCII.get();
      }
      auto translated_lines = TranslateInstruction(line, src_cpu, tgt_cpu,
                                                    save_vgpr_y + 1, cmpx_temp_sgpr, false,
                                                    src_opc, src_mcii);

      if (ii < source_instrs.size() && !branch_labels.empty()) {
        for (auto& t : translated_lines) {
          std::string tm = TranspileExtractMnemonic(t);
          if (tm.find("s_branch") == 0 || tm.find("s_cbranch_") == 0) {
            size_t op_pos = t.find(tm) + tm.size();
            std::string ops = t.substr(op_pos);
            size_t s = ops.find_first_not_of(" \t");
            if (s != std::string::npos) {
              std::string off_str = ops.substr(s);
              if (off_str.find(".L_") != 0) {
                {
                  int64_t raw = 0;
                  const char *fc_begin = off_str.data();
                  const char *fc_end = off_str.data() + off_str.size();
                  int fc_base = 10;
                  if (off_str.size() > 2 && off_str[0] == '0' &&
                      (off_str[1] == 'x' || off_str[1] == 'X')) {
                    fc_begin += 2;
                    fc_base = 16;
                  }
                  auto [fc_p, fc_ec] = std::from_chars(fc_begin, fc_end, raw, fc_base);
                  if (fc_ec == std::errc()) {
                    int64_t simm16 = static_cast<int16_t>(raw & 0xFFFF);
                    uint64_t target = source_instrs[ii].pc_offset + 4 + simm16 * 4;
                    uint64_t snapped = target;
                    for (const auto& si : source_instrs) {
                      if (si.pc_offset >= target) { snapped = si.pc_offset; break; }
                    }
                    auto lbl = branch_labels.find(snapped);
                    if (lbl != branch_labels.end()) t = tm + " " + lbl->second;
                  }
                }
              }
            }
          }
        }
      }

      bool translated_had_saveexec = false;
      uint32_t text_tgt_count = 0;
      std::string text_kind = "passthrough";
      for (const auto& t : translated_lines) {
        if (t.empty()) continue;
        if (t.find("saveexec") != std::string::npos) translated_had_saveexec = true;
        std::string m = TranspileExtractMnemonic(line);
        if (t.find("UNSUPPORTED") != std::string::npos) {
          ++stats.unsupported_skipped;
          text_kind = "unsupported";
        } else if (t != line) {
          std::string nm = TranspileExtractMnemonic(t);
          if (IsWaitInstruction(m)) {
            ++stats.translated_waitcnt;
            text_kind = "waitcnt";
          } else if (nm != m) {
            ++stats.translated_renamed;
            if (text_kind == "passthrough") text_kind = "renamed";
          } else if (t.find("exec_hi") != std::string::npos) {
            ++stats.translated_exec;
          } else {
            ++stats.translated_passthrough;
          }
        } else {
          ++stats.translated_passthrough;
        }
        translated_asm += t + "\n";
        ++text_tgt_count;
      }
      // Determine mapping kind based on output
      if (text_tgt_count == 0)
        text_kind = "eliminated";
      else if (text_tgt_count > 1 && text_kind != "waitcnt")
        text_kind = "expanded";
      if (ii < source_instrs.size()) {
        std::string m = TranspileExtractMnemonic(source_instrs[ii].text);
        mapping.entries.push_back({source_instrs[ii].pc_offset, m,
                                   source_instrs[ii].size, text_kind, text_tgt_count, {}});
        tgt_instr_count += text_tgt_count;
      }
      ++emitted_count;

      if (early_exit_after > 0 && emitted_count >= early_exit_after && !early_exit_done
          && source_lines.size() > 400) {
        for (size_t jj = ii + 1; jj < source_instrs.size(); jj++) {
          auto lbl = branch_labels.find(source_instrs[jj].pc_offset);
          if (lbl != branch_labels.end()) translated_asm += lbl->second + ":\n";
        }
        translated_asm += ".L_exit_k" + std::to_string(ki) + ":\ns_waitcnt vmcnt(0) lgkmcnt(0) expcnt(0)\n";
        translated_asm += "s_endpgm ; EARLY EXIT after " + std::to_string(emitted_count) + " instrs\n";
        early_exit_done = true;
        break;
      }

      if (ii < source_instrs.size()) {
        bool has_vcmpx = false;
        for (const auto& t : translated_lines)
          if (t.find("v_cmpx_") != std::string::npos) { has_vcmpx = true; break; }
        if (has_vcmpx) {
          if (source_lines.size() > 400) {
            translated_asm += "s_mov_b32 exec_hi, 0\n";
            if (!mapping.entries.empty()) { ++mapping.entries.back().tgt_count; ++tgt_instr_count; }
          } else {
            bool next_is_execz = false;
            for (size_t nxt = ii + 1; nxt < source_instrs.size(); nxt++) {
              std::string nm = TranspileExtractMnemonic(source_instrs[nxt].text);
              if (nm.find("s_delay") == 0 || nm.find("s_wait") == 0 || nm.find("s_nop") == 0 || nm.find("s_clause") == 0) continue;
              if (nm == "s_cbranch_execz") next_is_execz = true;
              break;
            }
            if (!next_is_execz) {
              translated_asm += "s_mov_b32 exec_hi, 0\n";
              if (!mapping.entries.empty()) { ++mapping.entries.back().tgt_count; ++tgt_instr_count; }
            }
          }
        }
      }

      if (translated_had_saveexec) {
        uint32_t extra = 0;
        for (auto& r : replace_regs) {
          translated_asm += "v_readfirstlane_b32 " + r.first + ", " + r.second + "\n";
          ++extra;
        }
        if (!mapping.entries.empty()) { mapping.entries.back().tgt_count += extra; tgt_instr_count += extra; }
      }
    }
  }

  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: translated "
            << stats.total_instructions << " instructions → "
            << stats.translated_passthrough << " passthrough, "
            << stats.translated_renamed << " renamed, "
            << stats.translated_waitcnt << " waitcnt, "
            << stats.translated_exec << " exec-widened, "
            << stats.unsupported_skipped << " unsupported\n";

  // Post-processing
  {
    auto replaceAll = [](std::string& s, const std::string& from, const std::string& to) {
      size_t pos = 0;
      while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
      }
    };
    // VCC branch fix
    {
      std::string tmp;
      std::istringstream vfix_iss(translated_asm);
      std::string vfix_line;
      while (std::getline(vfix_iss, vfix_line)) {
        if (vfix_line.find("s_cbranch_vccz") != std::string::npos ||
            vfix_line.find("s_cbranch_vccnz") != std::string::npos)
          tmp += "s_mov_b32 vcc_hi, 0\n";
        tmp += vfix_line + "\n";
      }
      translated_asm = tmp;
    }
    replaceAll(translated_asm, "v_add_nc_u32 ", "v_add_u32_e32 ");
    replaceAll(translated_asm, "v_sub_nc_u32 ", "v_sub_u32_e32 ");
    // Constant bus fix: VALU with two distinct SGPR sources
    {
      std::string tmp;
      std::istringstream cbus_iss(translated_asm);
      std::string cbus_line;
      const std::string vfix_reg = "v251";
      while (std::getline(cbus_iss, cbus_line)) {
        if (!cbus_line.empty() && cbus_line[0] == 'v' &&
            cbus_line.find("v_readfirstlane") != 0 &&
            cbus_line.find("v_writelane") != 0 &&
            cbus_line.find("v_readlane") != 0) {
          auto ops = ParseOperandList(cbus_line, TranspileExtractMnemonic(cbus_line));
          if (ops.size() >= 3) {
            std::string first_sgpr;
            size_t fix_idx = 0;
            for (size_t oi = 1; oi < ops.size(); ++oi) {
              std::string s = ops[oi];
              if (!s.empty() && s[0] == '-') s = s.substr(1);
              if (!s.empty() && s[0] == 's' && s.size() > 1 &&
                  (std::isdigit((unsigned char)s[1]) || s[1] == '[')) {
                if (first_sgpr.empty()) first_sgpr = s;
                else if (s != first_sgpr) { fix_idx = oi; break; }
              }
            }
            if (fix_idx > 0) {
              std::string op = ops[fix_idx];
              bool neg = !op.empty() && op[0] == '-';
              if (neg) op = op.substr(1);
              tmp += "v_mov_b32_e32 " + vfix_reg + ", " + op + "\n";
              ops[fix_idx] = (neg ? "-" : "") + vfix_reg;
              std::string mnem = TranspileExtractMnemonic(cbus_line);
              std::string fixed = mnem + " " + ops[0];
              for (size_t oi = 1; oi < ops.size(); ++oi) fixed += ", " + ops[oi];
              cbus_line = fixed;
            }
          }
        }
        tmp += cbus_line + "\n";
      }
      translated_asm = tmp;
    }
    // Strip explicit VCC mask from v_cndmask_b32_e32
    {
      std::string tmp;
      std::istringstream vcc_iss(translated_asm);
      std::string vcc_line;
      while (std::getline(vcc_iss, vcc_line)) {
        if (vcc_line.find("v_cndmask_b32_e32") != std::string::npos) {
          size_t vcc_pos = vcc_line.rfind(", vcc_lo");
          if (vcc_pos == std::string::npos) vcc_pos = vcc_line.rfind(", vcc");
          if (vcc_pos != std::string::npos)
            vcc_line = vcc_line.substr(0, vcc_pos);
        }
        tmp += vcc_line + "\n";
      }
      translated_asm = tmp;
    }
    // TRANS→VALU hazard mitigation for gfx942:
    // TODO(gfx950): verify whether this hazard applies to gfx950
    // When a TRANS instruction (v_exp_f32, v_rcp_f32, v_rsq_f32, v_sqrt_f32,
    // v_log_f32) writes a VGPR and the next instruction is a VALU that reads
    // the same VGPR, some lanes may read stale data. Insert v_nop between them.
    {
      auto IsTransInstr = [](const std::string& mnem) -> bool {
        return mnem.find("v_exp_f32") == 0 ||
               mnem.find("v_rcp_f32") == 0 ||
               mnem.find("v_rsq_f32") == 0 ||
               mnem.find("v_sqrt_f32") == 0 ||
               mnem.find("v_log_f32") == 0;
      };
      auto ExtractDstVgpr = [](const std::string& line, const std::string& mnem) -> std::string {
        size_t pos = line.find(mnem);
        if (pos == std::string::npos) return "";
        pos += mnem.size();
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
        if (pos >= line.size() || line[pos] != 'v') return "";
        size_t end = pos;
        while (end < line.size() && line[end] != ',' && line[end] != ' ' &&
               line[end] != '\t' && line[end] != ';') ++end;
        return line.substr(pos, end - pos);
      };
      auto LineReadsVgpr = [](const std::string& line, const std::string& vgpr) -> bool {
        if (vgpr.empty()) return false;
        // Check if vgpr appears as a source operand (after the first comma)
        size_t comma = line.find(',');
        if (comma == std::string::npos) return false;
        std::string rest = line.substr(comma);
        size_t pos = 0;
        while ((pos = rest.find(vgpr, pos)) != std::string::npos) {
          // Verify it's a whole word (not part of a longer register name)
          size_t end = pos + vgpr.size();
          bool word_end = (end >= rest.size() ||
                           rest[end] == ',' || rest[end] == ' ' ||
                           rest[end] == '\t' || rest[end] == ';' ||
                           rest[end] == ':' || rest[end] == ']');
          if (word_end) return true;
          pos = end;
        }
        return false;
      };

      std::string tmp;
      std::istringstream trans_iss(translated_asm);
      std::string trans_line;
      std::string prev_trans_dst; // VGPR written by previous TRANS instruction
      size_t trans_hazard_nops = 0;

      while (std::getline(trans_iss, trans_line)) {
        std::string mnem = TranspileExtractMnemonic(trans_line);
        // If previous was TRANS and current reads its destination, insert v_nop
        if (!prev_trans_dst.empty() && !mnem.empty() && mnem[0] == 'v' &&
            !IsTransInstr(mnem) &&
            LineReadsVgpr(trans_line, prev_trans_dst)) {
          tmp += "v_nop ; TRANS->VALU hazard\n";
          ++trans_hazard_nops;
        }
        tmp += trans_line + "\n";
        // Track TRANS destinations
        if (IsTransInstr(mnem))
          prev_trans_dst = ExtractDstVgpr(trans_line, mnem);
        else
          prev_trans_dst.clear();
      }
      translated_asm = tmp;
      if (trans_hazard_nops > 0) {
        HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: inserted " << trans_hazard_nops
                                          << " v_nop(s) for TRANS->VALU hazard mitigation\n";
      }
    }
    // Fix s_load from s[8:9]+0xc with saved kernarg ptr
    {
      if (translated_asm.find("s_load_dword s1, s[8:9], 0xc") != std::string::npos ||
          translated_asm.find("s_load_dword s0, s[8:9], 0xc") != std::string::npos) {
        std::string ka_pair = "s[30:31]";
        size_t ka_pos = translated_asm.find("; save kernarg ptr lo");
        if (ka_pos != std::string::npos) {
          size_t s_pos = translated_asm.rfind("s_mov_b32 s", ka_pos);
          if (s_pos != std::string::npos) {
            size_t n_start = s_pos + 11;
            size_t n_end = translated_asm.find(',', n_start);
            int lo = 0;
            std::from_chars(translated_asm.data() + n_start, translated_asm.data() + n_end, lo);
            ka_pair = "s[" + std::to_string(lo) + ":" + std::to_string(lo + 1) + "]";
          }
        } else {
          size_t insert_pos = translated_asm.find("; save workgroup_id_y\n");
          if (insert_pos != std::string::npos) {
            insert_pos = translated_asm.find('\n', insert_pos) + 1;
            translated_asm.insert(insert_pos,
              "s_mov_b32 s30, s0 ; save kernarg ptr lo\n"
              "s_mov_b32 s31, s1 ; save kernarg ptr hi\n");
          }
        }
        replaceAll(translated_asm, "s_load_dword s1, s[8:9], 0xc",
                   "s_load_dword s1, " + ka_pair + ", 0x3c");
        replaceAll(translated_asm, "s_load_dword s0, s[8:9], 0xc",
                   "s_load_dword s0, " + ka_pair + ", 0x3c");
      }
    }
  }

  if (std::getenv("HSA_HOTSWAP_DUMP")) {
    HotswapLog(HotswapLogLevel::Debug) << "hotswap: transpile: === TRANSLATED ASSEMBLY ===\n"
              << translated_asm
              << "hotswap: transpile: === END ASSEMBLY ===\n";
  }
  if (auto* asm_path = std::getenv("HSA_HOTSWAP_DUMP_ASM")) {
    FILE* af = fopen(asm_path, "w");
    if (af) { fwrite(translated_asm.data(), 1, translated_asm.size(), af); fclose(af); }
  }

  // Assemble translated text for target ISA
  llvm::Triple tgt_triple("amdgcn-amd-amdhsa");
  llvm::MCTargetOptions mc_opts;

  tgt_state.Ctx->reset();

  llvm::StringRef asm_ref(translated_asm);
  auto buf = llvm::MemoryBuffer::getMemBuffer(asm_ref, "", false);
  llvm::SourceMgr src_mgr;
  src_mgr.AddNewSourceBuffer(std::move(buf), llvm::SMLoc());

  std::string data;
  auto data_stream = std::make_unique<llvm::raw_string_ostream>(data);
  auto bos = std::make_unique<llvm::buffer_ostream>(*data_stream);

  llvm::MCCodeEmitter* ce = tgt_state.target->createMCCodeEmitter(*tgt_state.MCII, *tgt_state.Ctx);
  llvm::MCAsmBackend* mab = tgt_state.target->createMCAsmBackend(*tgt_state.STI, *tgt_state.MRI, mc_opts);

  if (!ce || !mab) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to create code emitter/backend\n";
    return AMD_COMGR_STATUS_ERROR;
  }

#if LLVM_VERSION_MAJOR > 20
  auto streamer = std::unique_ptr<llvm::MCStreamer>(
      tgt_state.target->createMCObjectStreamer(
          tgt_triple, *tgt_state.Ctx,
          std::unique_ptr<llvm::MCAsmBackend>(mab),
          mab->createObjectWriter(*bos),
          std::unique_ptr<llvm::MCCodeEmitter>(ce), *tgt_state.STI));
#else
  auto streamer = std::unique_ptr<llvm::MCStreamer>(
      tgt_state.target->createMCObjectStreamer(
          tgt_triple, *tgt_state.Ctx,
          std::unique_ptr<llvm::MCAsmBackend>(mab),
          mab->createObjectWriter(*bos),
          std::unique_ptr<llvm::MCCodeEmitter>(ce), *tgt_state.STI,
          mc_opts.MCRelaxAll, mc_opts.MCIncrementalLinkerCompatible, false));
#endif

  if (!streamer) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to create MC streamer\n";
    return AMD_COMGR_STATUS_ERROR;
  }

  auto parser = std::unique_ptr<llvm::MCAsmParser>(
      llvm::createMCAsmParser(src_mgr, *tgt_state.Ctx, *streamer, *tgt_state.MAI));
  auto tap = std::unique_ptr<llvm::MCTargetAsmParser>(
      tgt_state.target->createMCAsmParser(*tgt_state.STI, *parser, *tgt_state.MCII, mc_opts));
  if (!tap) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to create target asm parser\n";
    return AMD_COMGR_STATUS_ERROR;
  }
  parser->setTargetParser(*tap);

  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: starting assembly (" << translated_asm.size() << " chars)...\n";
  bool asm_failed = parser->Run(true);
  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: assembly finished (failed=" << asm_failed << ")\n";
  tap.reset();
  parser.reset();
  streamer.reset();
  bos.reset();
  data_stream->flush();
  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: streamer flushed, data size=" << data.size() << "\n";

  if (asm_failed)
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: assembly failed for " << tgt_cpu << "\n";

  if (data.size() < 64) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: assembled output too small (" << data.size() << " bytes)\n";
    return AMD_COMGR_STATUS_ERROR;
  }

  // Extract .text from assembled ELF
  const uint8_t* asm_elf = reinterpret_cast<const uint8_t*>(data.data());
  ElfInfo asm_info;
  if (!ParseElfInfo(asm_elf, data.size(), asm_info)) {
    HotswapLog(HotswapLogLevel::Error) << "hotswap: transpile: failed to parse assembled ELF\n";
    return AMD_COMGR_STATUS_ERROR;
  }

  const uint8_t* new_text = asm_elf + asm_info.text_offset;
  uint64_t new_text_size = asm_info.text_size;

  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: assembled " << new_text_size
            << " bytes (original: " << elf_info.text_size << ")\n";

  // Resolve target PC offsets for mapping entries by disassembling target .text
  {
    std::vector<uint64_t> tgt_offsets;
    uint64_t tpos = 0;
    while (tpos < new_text_size) {
      tgt_offsets.push_back(tpos);
      llvm::MCInst tinst;
      uint64_t tsize = 0;
      llvm::ArrayRef<uint8_t> tbytes(new_text + tpos, new_text_size - tpos);
      auto tst = tgt_state.disasm->getInstruction(tinst, tsize, tbytes, tpos, llvm::nulls());
      if (tst == llvm::MCDisassembler::Fail || tsize == 0)
        tpos += 4;
      else
        tpos += tsize;
    }
    // Walk mapping entries and assign target offsets sequentially
    // Skip preamble instructions (2 v_mov_b32 for workgroup id save)
    size_t tgt_idx = 2; // skip preamble
    for (auto& entry : mapping.entries) {
      entry.tgt_offsets.clear();
      for (uint32_t j = 0; j < entry.tgt_count && tgt_idx < tgt_offsets.size(); ++j, ++tgt_idx)
        entry.tgt_offsets.push_back(tgt_offsets[tgt_idx]);
    }
    HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: resolved " << tgt_offsets.size()
              << " target instruction offsets for " << mapping.entries.size() << " mapping entries\n";
  }

  // Replace .text in a NEW writable ELF buffer
  {
    size_t new_elf_size = size;
    MallocBuffer new_buf(new_elf_size);
    if (!new_buf) return AMD_COMGR_STATUS_ERROR;
    uint8_t *new_elf = new_buf.data;
    std::memcpy(new_elf, elf, size);

    if (new_text_size <= elf_info.text_size) {
      std::memcpy(new_elf + elf_info.text_offset, new_text, new_text_size);
      uint8_t nop_bytes[] = {0x00, 0x00, 0x80, 0xBF};
      for (uint64_t i = new_text_size; i + 4 <= elf_info.text_size; i += 4)
        std::memcpy(new_elf + elf_info.text_offset + i, nop_bytes, 4);
    } else {
      uint64_t available = elf_info.text_size;
      uint64_t next_section_start = new_elf_size;
      uint16_t e_shentsize, e_shnum;
      std::memcpy(&e_shentsize, new_elf + 58, 2);
      std::memcpy(&e_shnum, new_elf + 60, 2);
      uint64_t e_shoff;
      std::memcpy(&e_shoff, new_elf + 40, 8);
      for (uint16_t i = 0; i < e_shnum; ++i) {
        uint64_t sh_off = e_shoff + i * e_shentsize;
        if (sh_off + e_shentsize > new_elf_size) break;
        uint64_t sec_offset, sec_size;
        std::memcpy(&sec_offset, new_elf + sh_off + 24, 8);
        std::memcpy(&sec_size, new_elf + sh_off + 32, 8);
        if (sec_offset > elf_info.text_offset && sec_offset < next_section_start && sec_size > 0)
          next_section_start = sec_offset;
      }
      available = next_section_start - elf_info.text_offset;

      if (new_text_size <= available) {
        std::memcpy(new_elf + elf_info.text_offset, new_text, new_text_size);
        for (uint16_t i = 0; i < e_shnum; ++i) {
          uint64_t sh_off = e_shoff + i * e_shentsize;
          if (static_cast<int>(i) == elf_info.text_idx) {
            std::memcpy(new_elf + sh_off + 32, &new_text_size, 8);
            break;
          }
        }
      } else {
        uint64_t text_end = elf_info.text_offset + elf_info.text_size;
        uint64_t delta = ((new_text_size - elf_info.text_size + 255u) / 256u) * 256u;
        uint64_t grown_size = new_elf_size + delta;
        MallocBuffer grown_buf(grown_size);
        if (!grown_buf) return AMD_COMGR_STATUS_ERROR;
        std::memset(grown_buf.data, 0, grown_size);
        uint8_t *grown = grown_buf.data;
        std::memcpy(grown, new_elf, text_end);
        std::memcpy(grown + elf_info.text_offset, new_text, new_text_size);
        uint64_t new_sec_size = elf_info.text_size + delta;
        for (uint64_t p = new_text_size; p < new_sec_size; p += 4) {
          uint8_t nop[] = {0x00, 0x00, 0x80, 0xBF};
          std::memcpy(grown + elf_info.text_offset + p, nop, 4);
        }
        uint64_t tail = new_elf_size - text_end;
        if (tail > 0) std::memcpy(grown + text_end + delta, new_elf + text_end, tail);
        std::memcpy(&e_shoff, grown + 40, 8);
        e_shoff += delta;
        std::memcpy(grown + 40, &e_shoff, 8);
        for (uint16_t i = 0; i < e_shnum; ++i) {
          uint64_t sh_off = e_shoff + i * e_shentsize;
          uint64_t sec_offset;
          std::memcpy(&sec_offset, grown + sh_off + 24, 8);
          if (sec_offset > elf_info.text_offset) {
            sec_offset += delta;
            std::memcpy(grown + sh_off + 24, &sec_offset, 8);
          }
          if (static_cast<int>(i) == elf_info.text_idx)
            std::memcpy(grown + sh_off + 32, &new_sec_size, 8);
        }
        uint64_t e_phoff;
        uint16_t e_phentsize, e_phnum;
        std::memcpy(&e_phoff, grown + 32, 8);
        std::memcpy(&e_phentsize, grown + 54, 2);
        std::memcpy(&e_phnum, grown + 56, 2);
        for (uint16_t i = 0; i < e_phnum; ++i) {
          uint64_t ph_off = e_phoff + i * e_phentsize;
          if (ph_off + 56 > grown_size) break;
          uint64_t p_offset, p_filesz, p_memsz;
          std::memcpy(&p_offset, grown + ph_off + 8, 8);
          std::memcpy(&p_filesz, grown + ph_off + 32, 8);
          std::memcpy(&p_memsz, grown + ph_off + 40, 8);
          if (p_offset == elf_info.text_offset) {
            p_filesz += delta; p_memsz += delta;
            std::memcpy(grown + ph_off + 32, &p_filesz, 8);
            std::memcpy(grown + ph_off + 40, &p_memsz, 8);
          } else if (p_offset > elf_info.text_offset) {
            p_offset += delta;
            std::memcpy(grown + ph_off + 8, &p_offset, 8);
          }
        }
        new_buf = std::move(grown_buf);
        new_elf = new_buf.data;
        new_elf_size = grown_size;
      }
    }

    *out_data = new_buf.release();
    *out_size = new_elf_size;

    // Patch kernel descriptors in .rodata for gfx9 target.
    // COv3 KD layout (64 bytes):
    //   [0:3]   group_segment_fixed_size
    //   [4:7]   private_segment_fixed_size
    //   [8:11]  kernarg_size
    //   [16:23] kernel_code_entry_byte_offset
    //   [44:47] compute_pgm_rsrc3
    //   [48:51] compute_pgm_rsrc1
    //   [52:55] compute_pgm_rsrc2
    //   [56:57] kernel_code_properties
    ElfInfo updated_info;
    if (ParseElfInfo(new_elf, new_elf_size, updated_info)) {
      PatchKernelDescriptorsForWave64(new_elf, new_elf_size, updated_info);
      for (auto& sec : updated_info.sections) {
        if (sec.name == ".rodata" && sec.size >= 64) {
          for (uint64_t off = 0; off + 64 <= sec.size; off += 64) {
            uint8_t* desc = new_elf + sec.offset + off;
            // Filter: kernel_code_entry_byte_offset at offset 16 should be
            // non-zero for a valid KD, read as 8 bytes.
            uint64_t entry_check;
            std::memcpy(&entry_check, desc + 16, 8);
            if (entry_check == 0 || entry_check > 1000000) continue;

            // Read RSRC1 from correct COv3 offset (48)
            uint32_t rsrc1;
            std::memcpy(&rsrc1, desc + 48, 4);

            // GFX12 RSRC1 VGPR field: bits [5:0], granularity 12
            // GFX12 RSRC1 SGPR field: bits [11:6], granularity 16
            uint32_t vgpr_field12 = rsrc1 & 0x3Fu;
            uint32_t sgpr_field12 = (rsrc1 >> 6) & 0x3Fu;
            uint32_t num_vgprs = (vgpr_field12 + 1u) * 12u;
            if (num_vgprs < 8u) num_vgprs = 8u;
            num_vgprs += 4u;
            // WMMA→MFMA handler uses temp VGPRs at v248-v253 (6 regs)
            uint32_t wmma_temp_max = 248u + 6u;
            if (wmma_temp_max > num_vgprs) num_vgprs = wmma_temp_max;
            // GFX9 RSRC1 VGPR granularity is 4
            uint32_t gfx9_vgpr = ((num_vgprs + 3u) / 4u) - 1u;
            if (gfx9_vgpr > 63u) gfx9_vgpr = 63u;

            // Compute GFX9 SGPR field
            uint32_t num_sgprs = (sgpr_field12 + 1u) * 16u + 8u;
            {
              const char* sgpr_key = ".sgpr_count";
              for (size_t si = 0; si + 12 < new_elf_size; si++) {
                if (std::memcmp(new_elf + si, sgpr_key, 11) == 0) {
                  uint8_t val = new_elf[si + 11];
                  uint32_t sc = (val <= 0x7F) ? val : (val == 0xCC ? new_elf[si+12] : 0);
                  if (sc + 8 > num_sgprs) num_sgprs = sc + 8;
                  break;
                }
              }
            }
            // GFX9 SGPR granularity is 8, field is bits [9:6] (4 bits, max 12)
            uint32_t gfx9_sgpr = (num_sgprs / 8u) - 1u;
            if (gfx9_sgpr > 12u) gfx9_sgpr = 12u;

            // Rebuild RSRC1 for GFX9: preserve FLOAT_MODE and other upper bits
            rsrc1 &= 0x00FFF000u; // keep bits [23:12] (FLOAT_MODE, PRIV, etc.)
            rsrc1 |= (1u << 21) | (1u << 23); // IEEE_MODE, FP16_OVFL
            rsrc1 |= (gfx9_vgpr & 0x3Fu);        // bits [5:0]
            rsrc1 |= (gfx9_sgpr << 6u);           // bits [9:6]
            std::memcpy(desc + 48, &rsrc1, 4);

            HotswapLog(HotswapLogLevel::Info)
                << "hotswap: transpile: KD RSRC1=0x" << std::hex << rsrc1
                << " (vgprs=" << std::dec << ((gfx9_vgpr + 1u) * 4u)
                << ", sgprs=" << num_sgprs << ")\n";

            // Patch RSRC2 at offset 52 for GFX9:
            // - USER_SGPR_COUNT=2: s[0:1]=kernarg ptr (ENABLE_SGPR_KERNARG_SEGMENT_PTR)
            // - ENABLE_SGPR_WORKGROUP_ID X/Y/Z: system SGPRs after user SGPRs
            // - ENABLE_VGPR_WORKITEM_ID=1: v0=workitem_x, v1=workitem_y
            // - Clear ENABLE_SGPR_WORKGROUP_INFO (bit 10): inherited from
            //   GFX12 where it may mean something different; on GFX9 it adds
            //   an extra SGPR that shifts system SGPR layout.
            uint32_t rsrc2;
            std::memcpy(&rsrc2, desc + 52, 4);
            rsrc2 |= (1u << 7) | (1u << 8) | (1u << 9); // WG_ID X/Y/Z
            rsrc2 &= ~(1u << 10);                         // clear WG_INFO
            rsrc2 = (rsrc2 & ~(0x3u << 11)) | (1u << 11); // WORKITEM_ID=1 (X+Y)
            rsrc2 = (rsrc2 & ~(0x1Fu << 1)) | (2u << 1);  // USER_SGPR_COUNT=2
            std::memcpy(desc + 52, &rsrc2, 4);

            HotswapLog(HotswapLogLevel::Info)
                << "hotswap: transpile: KD RSRC2=0x" << std::hex << rsrc2 << "\n";

            // Patch kernel_code_properties at offset 56:
            // - Clear ENABLE_WAVEFRONT_SIZE32 (bit 10) for wave64
            // - Set ENABLE_SGPR_KERNARG_SEGMENT_PTR (bit 3)
            uint16_t props;
            std::memcpy(&props, desc + 56, 2);
            props = static_cast<uint16_t>(
                ((static_cast<uint32_t>(props) & ~(1u << 10)) | (1u << 3)) & 0xFFFFu);
            std::memcpy(desc + 56, &props, 2);

            // Patch RSRC3 at offset 44: set ACCUM_OFFSET for gfx9
            // GFX9 RSRC3 bits [5:0] = ACCUM_OFFSET = (num_accvgprs/4 - 1)
            // Use same value as gfx9_vgpr (allocate all VGPRs as accum-capable)
            uint32_t rsrc3 = gfx9_vgpr;
            std::memcpy(desc + 44, &rsrc3, 4);

            HotswapLog(HotswapLogLevel::Info)
                << "hotswap: transpile: KD RSRC3=0x" << std::hex << rsrc3
                << " (accum_offset=" << std::dec << gfx9_vgpr << ")\n";
          }
        }
      }
    }

    // Patch ELF metadata
    PatchElfMetadata(new_elf, new_elf_size, tgt_cpu);
  }

  result->rules_matched = stats.translated_passthrough + stats.translated_renamed + stats.translated_waitcnt;

  HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: complete (" << src_cpu << " → " << tgt_cpu << ")\n";

  if (auto* dump_path = std::getenv("HSA_HOTSWAP_DUMP_ELF")) {
    FILE* fp = fopen(dump_path, "wb");
    if (fp) {
      fwrite(*out_data, 1, *out_size, fp);
      fclose(fp);
      HotswapLog(HotswapLogLevel::Debug) << "hotswap: transpile: dumped patched ELF to " << dump_path << "\n";
    }
  }

  if (auto* map_path = std::getenv("HSA_HOTSWAP_DUMP_MAPPING")) {
    mapping.emitJSON(map_path);
    HotswapLog(HotswapLogLevel::Info) << "hotswap: transpile: dumped mapping JSON ("
              << mapping.entries.size() << " entries) to " << map_path << "\n";
  }

  return AMD_COMGR_STATUS_SUCCESS;
}

// ── retargetCodeObjectTranspile ──────────────────────────────────────────────
//
// Entry point conforming to the COMGR::hotswap internal API. Bridges the
// TargetIdentifier-based interface used by the comgr public API to the
// string-based TranspileCodeObject pipeline above.

namespace COMGR {
namespace hotswap {

amd_comgr_status_t
retargetCodeObjectTranspile(const void *ElfData, size_t ElfSize,
                            const TargetIdentifier &SourceIdent,
                            const TargetIdentifier &TargetIdent,
                            std::unique_ptr<llvm::MemoryBuffer> &Out) {
  // Build full ISA strings from the parsed TargetIdentifiers.
  // Format: "<arch>-<vendor>-<os>--<processor>"
  std::string SourceIsa =
      (SourceIdent.Arch + "-" + SourceIdent.Vendor + "-" + SourceIdent.OS +
       "--" + SourceIdent.Processor)
          .str();
  std::string TargetIsa =
      (TargetIdent.Arch + "-" + TargetIdent.Vendor + "-" + TargetIdent.OS +
       "--" + TargetIdent.Processor)
          .str();

  void *OutData = nullptr;
  size_t OutSize = 0;
  amd_comgr_hotswap_result_t Result = {};

  amd_comgr_status_t Status = TranspileCodeObject(
      ElfData, ElfSize, SourceIsa, TargetIsa, &OutData, &OutSize, &Result);
  if (Status != AMD_COMGR_STATUS_SUCCESS)
    return Status;
  if (!OutData || OutSize == 0)
    return AMD_COMGR_STATUS_ERROR;

  // Wrap the malloc'd buffer in a MemoryBuffer. WritableMemoryBuffer takes
  // ownership through a copy, then we free the original allocation.
  Out = llvm::WritableMemoryBuffer::getNewUninitMemBuffer(OutSize);
  if (!Out) {
    free(OutData);
    return AMD_COMGR_STATUS_ERROR_OUT_OF_RESOURCES;
  }
  std::memcpy(
      const_cast<char *>(Out->getBufferStart()), OutData, OutSize);
  free(OutData);

  return AMD_COMGR_STATUS_SUCCESS;
}

} // namespace hotswap
} // namespace COMGR
