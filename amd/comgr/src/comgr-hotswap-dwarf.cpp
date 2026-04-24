//===- comgr-hotswap-dwarf.cpp - DWARF / debug update helpers -------------===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

// ── LEB128 helpers (file-local) ──────────────────────────────────────────────

static void EncodeSLEB128(int64_t value, std::vector<uint8_t> &out) {
  uint8_t buf[16];
  unsigned n = llvm::encodeSLEB128(value, buf);
  out.insert(out.end(), buf, buf + n);
}

static uint64_t DecodeULEB128(const uint8_t *p, size_t *n) {
  unsigned nn = 0;
  uint64_t result = llvm::decodeULEB128(p, &nn);
  *n = nn;
  return result;
}

static int64_t DecodeSLEB128(const uint8_t *p, size_t *n) {
  unsigned nn = 0;
  int64_t result = llvm::decodeSLEB128(p, &nn);
  *n = nn;
  return result;
}

// ── FindSectionHeader ────────────────────────────────────────────────────────

uint8_t *FindSectionHeader(uint8_t *elf, size_t elf_size,
                                   const char *name, int *out_idx) {
  if (elf_size < 64) return nullptr;
  uint64_t e_shoff;
  uint16_t e_shentsize, e_shnum, e_shstrndx;
  std::memcpy(&e_shoff, elf + 40, 8);
  std::memcpy(&e_shentsize, elf + 58, 2);
  std::memcpy(&e_shnum, elf + 60, 2);
  std::memcpy(&e_shstrndx, elf + 62, 2);
  if (e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum) return nullptr;
  if (e_shoff + static_cast<uint64_t>(e_shnum) * e_shentsize > elf_size)
    return nullptr;
  uint8_t *shstr_sh = elf + e_shoff + e_shstrndx * e_shentsize;
  uint64_t shstr_off, shstr_sz;
  std::memcpy(&shstr_off, shstr_sh + 24, 8);
  std::memcpy(&shstr_sz, shstr_sh + 32, 8);
  if (shstr_off + shstr_sz > elf_size) return nullptr;
  const char *shstrtab = reinterpret_cast<const char *>(elf + shstr_off);

  for (uint16_t i = 0; i < e_shnum; ++i) {
    uint8_t *sh = elf + e_shoff + i * e_shentsize;
    uint32_t sh_name;
    std::memcpy(&sh_name, sh, 4);
    if (sh_name < shstr_sz && std::strcmp(shstrtab + sh_name, name) == 0) {
      if (out_idx) *out_idx = i;
      return sh;
    }
  }
  return nullptr;
}

// ── AddTrampolineSymbols ─────────────────────────────────────────────────────

[[nodiscard]] bool AddTrampolineSymbols(
    MallocBuffer &elf_buf,
    const std::vector<Trampoline> &trampolines,
    uint64_t text_size_before, int text_section_idx) {
  if (trampolines.empty()) return true;

  uint8_t *elf = elf_buf.data;
  size_t elf_size = elf_buf.size;

  int symtab_idx = -1;
  uint8_t *symtab_sh = FindSectionHeader(elf, elf_size, ".symtab", &symtab_idx);
  if (!symtab_sh) return true;

  uint64_t symtab_offset, symtab_size;
  uint32_t symtab_link, symtab_info;
  std::memcpy(&symtab_offset, symtab_sh + 24, 8);
  std::memcpy(&symtab_size, symtab_sh + 32, 8);
  std::memcpy(&symtab_link, symtab_sh + 40, 4);
  std::memcpy(&symtab_info, symtab_sh + 44, 4);

  uint16_t e_shnum;
  std::memcpy(&e_shnum, elf + 60, 2);
  if (symtab_link >= e_shnum) return true;

  uint64_t e_shoff;
  uint16_t e_shentsize;
  std::memcpy(&e_shoff, elf + 40, 8);
  std::memcpy(&e_shentsize, elf + 58, 2);

  uint8_t *strtab_sh = elf + e_shoff + symtab_link * e_shentsize;
  uint64_t strtab_offset, strtab_size;
  std::memcpy(&strtab_offset, strtab_sh + 24, 8);
  std::memcpy(&strtab_size, strtab_sh + 32, 8);

  std::vector<std::string> names;
  std::vector<std::vector<uint8_t>> entries;
  uint64_t running = text_size_before;

  for (auto &t : trampolines) {
    std::ostringstream oss;
    oss << "__hotswap_tramp_" << std::hex << t.original_offset;
    names.push_back(oss.str());

    std::vector<uint8_t> entry(24, 0);
    entry[4] = 0x02;
    uint16_t shndx = static_cast<uint16_t>(text_section_idx);
    std::memcpy(entry.data() + 6, &shndx, 2);
    std::memcpy(entry.data() + 8, &running, 8);
    uint64_t sz = t.bytes.size();
    std::memcpy(entry.data() + 16, &sz, 8);
    entries.push_back(std::move(entry));
    running += t.bytes.size();
  }

  size_t extra_str = 0;
  for (auto &n : names) extra_str += n.size() + 1;
  size_t extra_sym = entries.size() * 24;
  size_t new_strtab_total = strtab_size + extra_str;
  size_t new_symtab_total = symtab_size + extra_sym;
  size_t new_elf_size = elf_size + new_strtab_total + new_symtab_total;

  MallocBuffer out_buf(new_elf_size);
  if (!out_buf) return false;
  uint8_t *out = out_buf.data;
  std::memcpy(out, elf, elf_size);

  uint64_t new_str_off = elf_size;
  std::memcpy(out + new_str_off, elf + strtab_offset, strtab_size);
  uint64_t npos = strtab_size;
  for (size_t i = 0; i < names.size(); ++i) {
    uint32_t st_name = static_cast<uint32_t>(npos);
    std::memcpy(entries[i].data(), &st_name, 4);
    std::memcpy(out + new_str_off + npos,
                names[i].c_str(), names[i].size() + 1);
    npos += names[i].size() + 1;
  }

  uint64_t new_sym_off = new_str_off + new_strtab_total;
  size_t old_sym_count = symtab_size / 24;
  size_t local_end = symtab_info;
  if (local_end > old_sym_count) local_end = old_sym_count;

  uint64_t wp = new_sym_off;
  std::memcpy(out + wp, elf + symtab_offset, local_end * 24);
  wp += local_end * 24;
  for (auto &e : entries) {
    std::memcpy(out + wp, e.data(), 24);
    wp += 24;
  }
  if (local_end < old_sym_count)
    std::memcpy(out + wp, elf + symtab_offset + local_end * 24,
                (old_sym_count - local_end) * 24);

  uint64_t cur_shoff;
  std::memcpy(&cur_shoff, out + 40, 8);
  uint8_t *new_str_sh = out + cur_shoff + symtab_link * e_shentsize;
  std::memcpy(new_str_sh + 24, &new_str_off, 8);
  uint64_t strsz64 = new_strtab_total;
  std::memcpy(new_str_sh + 32, &strsz64, 8);

  uint8_t *new_sym_sh = out + cur_shoff + symtab_idx * e_shentsize;
  std::memcpy(new_sym_sh + 24, &new_sym_off, 8);
  uint64_t symsz64 = new_symtab_total;
  std::memcpy(new_sym_sh + 32, &symsz64, 8);
  uint32_t new_info = static_cast<uint32_t>(local_end + entries.size());
  std::memcpy(new_sym_sh + 44, &new_info, 4);

  elf_buf = std::move(out_buf);
  return true;
}

// ── ScanDebugLineTable (file-local) ──────────────────────────────────────────

static std::vector<DebugLineRow> ScanDebugLineTable(
    const uint8_t *data, size_t data_size) {
  std::vector<DebugLineRow> rows;
  if (data_size < 15) return rows;

  uint32_t unit_length;
  std::memcpy(&unit_length, data, 4);
  size_t unit_end = 4 + unit_length;
  if (unit_end > data_size) unit_end = data_size;

  uint16_t version;
  std::memcpy(&version, data + 4, 2);

  uint32_t header_length;
  std::memcpy(&header_length, data + 6, 4);

  uint8_t min_inst_len = data[10];
  size_t hp = 11;
  if (version >= 4 && hp < unit_end) hp++;
  if (hp + 3 >= unit_end) return rows;
  int8_t line_base = static_cast<int8_t>(data[hp + 1]);
  uint8_t line_range = data[hp + 2];
  uint8_t opcode_base = data[hp + 3];
  hp += 4;
  if (line_range == 0) return rows;

  std::vector<uint8_t> std_lens(opcode_base > 0 ? opcode_base - 1 : 0);
  for (size_t i = 0; i < std_lens.size() && hp < unit_end; ++i)
    std_lens[i] = data[hp++];

  size_t prog_start = 10 + header_length;
  if (prog_start > unit_end) return rows;

  uint64_t addr = 0;
  uint32_t file = 1;
  int32_t line = 1;
  size_t pos = prog_start;

  while (pos < unit_end) {
    uint8_t op = data[pos++];
    if (op == 0) {
      if (pos >= unit_end) break;
      size_t nb;
      uint64_t ext_len = DecodeULEB128(data + pos, &nb);
      pos += nb;
      if (ext_len == 0 || pos + ext_len > unit_end) break;
      uint8_t ext_op = data[pos];
      if (ext_op == 1) {
        rows.push_back({addr, file, line});
        addr = 0; file = 1; line = 1;
      } else if (ext_op == 2) {
        if (ext_len >= 9)
          std::memcpy(&addr, data + pos + 1, 8);
        else if (ext_len >= 5) {
          uint32_t a; std::memcpy(&a, data + pos + 1, 4); addr = a;
        }
      }
      pos += ext_len;
    } else if (op < opcode_base) {
      switch (op) {
        case 1: rows.push_back({addr, file, line}); break;
        case 2: {
          size_t nb;
          addr += DecodeULEB128(data + pos, &nb) * min_inst_len;
          pos += nb; break;
        }
        case 3: {
          size_t nb;
          line += static_cast<int32_t>(DecodeSLEB128(data + pos, &nb));
          pos += nb; break;
        }
        case 4: {
          size_t nb;
          file = static_cast<uint32_t>(DecodeULEB128(data + pos, &nb));
          pos += nb; break;
        }
        case 5: { size_t nb; DecodeULEB128(data + pos, &nb); pos += nb; break; }
        case 6: case 7: break;
        case 8:
          addr += static_cast<uint64_t>((255 - opcode_base) / line_range) *
                  min_inst_len;
          break;
        case 9: {
          uint16_t a; std::memcpy(&a, data + pos, 2); pos += 2;
          addr += a; break;
        }
        default:
          if (op - 1 < static_cast<int>(std_lens.size()))
            for (uint8_t j = 0; j < std_lens[op - 1]; ++j) {
              size_t nb; DecodeULEB128(data + pos, &nb); pos += nb;
            }
          break;
      }
    } else {
      uint8_t adj = op - opcode_base;
      addr += static_cast<uint64_t>(adj / line_range) * min_inst_len;
      line += line_base + (adj % line_range);
      rows.push_back({addr, file, line});
    }
  }
  return rows;
}

// ── PatchDebugLine ───────────────────────────────────────────────────────────

[[nodiscard]] bool PatchDebugLine(
    MallocBuffer &elf_buf,
    const std::vector<Trampoline> &trampolines,
    uint64_t text_size_before, uint64_t text_addr) {
  if (trampolines.empty()) return true;

  uint8_t *elf = elf_buf.data;
  size_t elf_size = elf_buf.size;

  uint8_t *dl_sh = FindSectionHeader(elf, elf_size, ".debug_line");
  if (!dl_sh) return true;

  uint64_t dl_offset, dl_size;
  std::memcpy(&dl_offset, dl_sh + 24, 8);
  std::memcpy(&dl_size, dl_sh + 32, 8);
  if (dl_offset + dl_size > elf_size || dl_size < 15)
    return true;

  auto rows = ScanDebugLineTable(elf + dl_offset, dl_size);

  auto FindLine = [&](uint64_t off) -> int32_t {
    uint64_t target = text_addr + off;
    int32_t best = 1;
    uint64_t best_addr = 0;
    for (auto &r : rows) {
      if (r.address <= target && r.address >= best_addr) {
        best_addr = r.address;
        best = r.line;
      }
    }
    return best;
  };

  std::vector<uint8_t> extra;
  uint64_t running = text_size_before;
  for (auto &t : trampolines) {
    uint64_t tramp_addr = text_addr + running;
    uint64_t tramp_end = tramp_addr + t.bytes.size();
    int32_t src_line = FindLine(t.original_offset);

    extra.push_back(0x00); extra.push_back(0x09); extra.push_back(0x02);
    for (int b = 0; b < 8; ++b)
      extra.push_back(static_cast<uint8_t>(tramp_addr >> (b * 8)));

    if (src_line != 1) {
      extra.push_back(0x03);
      EncodeSLEB128(static_cast<int64_t>(src_line) - 1, extra);
    }

    extra.push_back(0x01);

    extra.push_back(0x00); extra.push_back(0x09); extra.push_back(0x02);
    for (int b = 0; b < 8; ++b)
      extra.push_back(static_cast<uint8_t>(tramp_end >> (b * 8)));

    extra.push_back(0x00); extra.push_back(0x01); extra.push_back(0x01);

    running += t.bytes.size();
  }

  if (extra.empty()) return true;

  size_t new_dl_size = dl_size + extra.size();
  size_t new_elf_size = elf_size + new_dl_size;
  MallocBuffer out_buf(new_elf_size);
  if (!out_buf) return false;
  uint8_t *out = out_buf.data;
  std::memcpy(out, elf, elf_size);

  uint64_t new_dl_off = elf_size;
  std::memcpy(out + new_dl_off, elf + dl_offset, dl_size);
  std::memcpy(out + new_dl_off + dl_size, extra.data(), extra.size());

  uint32_t old_ul;
  std::memcpy(&old_ul, out + new_dl_off, 4);
  uint32_t new_ul = old_ul + static_cast<uint32_t>(extra.size());
  std::memcpy(out + new_dl_off, &new_ul, 4);

  uint8_t *new_dl_sh = FindSectionHeader(out, new_elf_size, ".debug_line");
  if (new_dl_sh) {
    std::memcpy(new_dl_sh + 24, &new_dl_off, 8);
    uint64_t sz64 = new_dl_size;
    std::memcpy(new_dl_sh + 32, &sz64, 8);
  }

  elf_buf = std::move(out_buf);
  return true;
}

// ── PatchDebugRanges ─────────────────────────────────────────────────────────

void PatchDebugRanges(uint8_t *elf, size_t elf_size,
                              uint64_t text_addr, uint64_t text_size_before,
                              uint64_t tramp_total) {
  uint8_t *sh = FindSectionHeader(elf, elf_size, ".debug_ranges");
  if (!sh) return;
  uint64_t offset, size;
  std::memcpy(&offset, sh + 24, 8);
  std::memcpy(&size, sh + 32, 8);
  if (offset + size > elf_size) return;

  uint64_t text_end = text_addr + text_size_before;
  uint8_t *d = elf + offset;
  for (size_t i = 0; i + 16 <= size; i += 16) {
    uint64_t s, e;
    std::memcpy(&s, d + i, 8);
    std::memcpy(&e, d + i + 8, 8);
    if (s == 0 && e == 0) continue;
    if (e > text_addr && e <= text_end) {
      uint64_t new_e = e + tramp_total;
      std::memcpy(d + i + 8, &new_e, 8);
    }
  }
}

// ── PatchDebugInfo ───────────────────────────────────────────────────────────

void PatchDebugInfo(uint8_t *elf, size_t elf_size,
                            uint64_t text_addr, uint64_t text_size_before,
                            uint64_t tramp_total) {
  uint8_t *sh = FindSectionHeader(elf, elf_size, ".debug_info");
  if (!sh) return;
  uint64_t offset, size;
  std::memcpy(&offset, sh + 24, 8);
  std::memcpy(&size, sh + 32, 8);
  if (offset + size > elf_size) return;

  uint8_t *d = elf + offset;
  uint64_t new_text_size = text_size_before + tramp_total;

  for (size_t i = 0; i + 12 <= size; ++i) {
    uint64_t v;
    std::memcpy(&v, d + i, 8);
    if (v != text_addr) continue;

    uint32_t hp4;
    std::memcpy(&hp4, d + i + 8, 4);
    if (hp4 > 0 && hp4 <= static_cast<uint32_t>(text_size_before)) {
      uint32_t ns4 = static_cast<uint32_t>(new_text_size);
      std::memcpy(d + i + 8, &ns4, 4);
      i += 11; continue;
    }
    if (i + 16 <= size) {
      uint64_t hp8;
      std::memcpy(&hp8, d + i + 8, 8);
      if (hp8 > 0 && hp8 <= text_size_before) {
        std::memcpy(d + i + 8, &new_text_size, 8);
        i += 15; continue;
      }
      if (hp8 > text_addr && hp8 <= text_addr + text_size_before) {
        uint64_t new_abs = text_addr + new_text_size;
        std::memcpy(d + i + 8, &new_abs, 8);
        i += 15; continue;
      }
    }
  }
}

// ── PatchDebugFrame ──────────────────────────────────────────────────────────

void PatchDebugFrame(uint8_t *elf, size_t elf_size,
                              uint64_t text_addr, uint64_t text_size_before,
                              uint64_t tramp_total) {
  uint8_t *sh = FindSectionHeader(elf, elf_size, ".debug_frame");
  if (!sh) return;
  uint64_t offset, size;
  std::memcpy(&offset, sh + 24, 8);
  std::memcpy(&size, sh + 32, 8);
  if (offset + size > elf_size) return;

  uint8_t *d = elf + offset;
  uint64_t new_text_size = text_size_before + tramp_total;
  size_t pos = 0;
  while (pos + 12 <= size) {
    uint32_t length;
    std::memcpy(&length, d + pos, 4);
    if (length == 0 || length == 0xFFFFFFFF) break;
    size_t entry_end = pos + 4 + length;
    if (entry_end > size) break;

    uint32_t cie_id;
    std::memcpy(&cie_id, d + pos + 4, 4);
    if (cie_id != 0xFFFFFFFF && length >= 20 && pos + 24 <= size) {
      uint64_t init_loc, addr_range;
      std::memcpy(&init_loc, d + pos + 8, 8);
      std::memcpy(&addr_range, d + pos + 16, 8);
      if (init_loc == text_addr && addr_range > 0 &&
          addr_range <= text_size_before) {
        std::memcpy(d + pos + 16, &new_text_size, 8);
      }
    }
    pos = entry_end;
  }
}
