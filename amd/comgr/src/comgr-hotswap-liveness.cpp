//===- comgr-hotswap-liveness.cpp - CFG, backward liveness, scratch alloc -===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

// ── Per-point VGPR liveness analysis ─────────────────────────────────────────

RegDefUse GetInstRegDefUse(const llvm::MCInst &inst,
                                  const llvm::MCInstrInfo &MCII,
                                  const llvm::MCRegisterInfo &MRI) {
  RegDefUse du;
  const llvm::MCInstrDesc &desc = MCII.get(inst.getOpcode());

  auto addVgprRange = [&](unsigned reg, llvm::BitVector &out) {
    auto [base, count] = GetVgprRange(reg, MRI);
    if (base >= 0) {
      for (int v = base; v < base + count; ++v)
        out.set(v);
    }
  };

  unsigned num_defs = desc.getNumDefs();
  for (unsigned i = 0; i < inst.getNumOperands(); ++i) {
    const auto &op = inst.getOperand(i);
    if (!op.isReg()) continue;
    if (i < num_defs)
      addVgprRange(op.getReg(), du.defs);
    else
      addVgprRange(op.getReg(), du.uses);
  }

  for (llvm::MCPhysReg r : desc.implicit_defs())
    addVgprRange(r, du.defs);
  for (llvm::MCPhysReg r : desc.implicit_uses())
    addVgprRange(r, du.uses);

  return du;
}

// ── CFG construction ─────────────────────────────────────────────────────────

int64_t GetBranchImm(const llvm::MCInst &inst) {
  for (unsigned i = 0; i < inst.getNumOperands(); ++i) {
    if (inst.getOperand(i).isImm())
      return inst.getOperand(i).getImm();
  }
  return 0;
}

// ── Opcode-based classification via MCInstrDesc ──────────────────────────────

static bool IsBranchOpcode(unsigned opcode, const llvm::MCInstrInfo &MCII) {
  const llvm::MCInstrDesc &desc = MCII.get(opcode);
  return desc.isUnconditionalBranch();
}

static bool IsCBranchOpcode(unsigned opcode, const llvm::MCInstrInfo &MCII) {
  const llvm::MCInstrDesc &desc = MCII.get(opcode);
  return desc.isConditionalBranch();
}

static bool IsTerminator(unsigned opcode, const llvm::MCInstrInfo &MCII) {
  const llvm::MCInstrDesc &desc = MCII.get(opcode);
  return desc.isTerminator();
}

static bool IsCall(unsigned opcode, const llvm::MCInstrInfo &MCII) {
  const llvm::MCInstrDesc &desc = MCII.get(opcode);
  return desc.isCall();
}

static bool IsReturn(unsigned opcode, const llvm::MCInstrInfo &MCII) {
  const llvm::MCInstrDesc &desc = MCII.get(opcode);
  return desc.isReturn();
}

// ── Opcode-based CFG construction ────────────────────────────────────────────

CFG BuildCFG(const std::vector<InternalDecodedInst> &decoded,
             const llvm::MCInstrInfo &MCII) {
  CFG cfg;
  if (decoded.empty()) return cfg;

  std::set<uint64_t> bb_starts;
  bb_starts.insert(decoded[0].offset);

  uint64_t text_end = decoded.back().offset + decoded.back().size;

  for (size_t i = 0; i < decoded.size(); ++i) {
    const auto &di = decoded[i];
    unsigned opc = di.inst.getOpcode();
    const llvm::MCInstrDesc &desc = MCII.get(opc);
    bool is_branch = IsBranchOpcode(opc, MCII) && !desc.isIndirectBranch();
    bool is_cbranch = IsCBranchOpcode(opc, MCII);

    if (is_branch || is_cbranch) {
      int64_t imm = GetBranchImm(di.inst);
      uint64_t target = di.offset + 4 + (imm * 4);
      if (target < text_end)
        bb_starts.insert(target);
      if (i + 1 < decoded.size())
        bb_starts.insert(decoded[i + 1].offset);
    }

    if (IsTerminator(opc, MCII) && !is_branch && !is_cbranch) {
      if (i + 1 < decoded.size())
        bb_starts.insert(decoded[i + 1].offset);
    }

    if (IsCall(opc, MCII) && !IsTerminator(opc, MCII)) {
      int64_t imm = GetBranchImm(di.inst);
      if (imm != INT64_MIN) {
        uint64_t target = di.offset + 4 + static_cast<int64_t>(imm) * 4;
        if (target < text_end)
          bb_starts.insert(target);
      }
      if (i + 1 < decoded.size())
        bb_starts.insert(decoded[i + 1].offset);
    }
  }

  std::vector<uint64_t> sorted_starts(bb_starts.begin(), bb_starts.end());
  std::sort(sorted_starts.begin(), sorted_starts.end());

  for (int i = 0; i < static_cast<int>(sorted_starts.size()); ++i)
    cfg.offset_to_block[sorted_starts[i]] = i;

  cfg.blocks.resize(sorted_starts.size());
  for (size_t i = 0; i < sorted_starts.size(); ++i)
    cfg.blocks[i].start_offset = sorted_starts[i];

  int current_block = -1;
  for (size_t i = 0; i < decoded.size(); ++i) {
    auto it = cfg.offset_to_block.find(decoded[i].offset);
    if (it != cfg.offset_to_block.end())
      current_block = it->second;
    if (current_block >= 0 &&
        current_block < static_cast<int>(cfg.blocks.size())) {
      cfg.blocks[current_block].inst_indices.push_back(i);
      cfg.blocks[current_block].end_offset =
          decoded[i].offset + decoded[i].size;
    }
  }

  for (int bi = 0; bi < static_cast<int>(cfg.blocks.size()); ++bi) {
    auto &bb = cfg.blocks[bi];
    if (bb.inst_indices.empty()) continue;

    size_t last_idx = bb.inst_indices.back();
    const auto &last = decoded[last_idx];
    unsigned last_opc = last.inst.getOpcode();
    const llvm::MCInstrDesc &desc = MCII.get(last_opc);

    bool is_branch = IsBranchOpcode(last_opc, MCII) && !desc.isIndirectBranch();
    bool is_cbranch = IsCBranchOpcode(last_opc, MCII);
    bool is_call = IsCall(last_opc, MCII);

    if (desc.isBarrier() && !desc.isBranch() && !is_call) {
      /* s_endpgm: no successors */
    } else if (IsReturn(last_opc, MCII) || desc.isIndirectBranch()) {
      /* s_setpc/s_swappc: conservative unknown targets */
    } else if (is_branch || is_cbranch) {
      int64_t imm = GetBranchImm(last.inst);
      uint64_t target = last.offset + 4 + (imm * 4);
      auto tgt_it = cfg.offset_to_block.find(target);
      if (tgt_it != cfg.offset_to_block.end())
        bb.successors.push_back(tgt_it->second);
      if (is_cbranch) {
        uint64_t fallthrough = last.offset + last.size;
        auto ft_it = cfg.offset_to_block.find(fallthrough);
        if (ft_it != cfg.offset_to_block.end())
          bb.successors.push_back(ft_it->second);
      }
    } else if (is_call) {
      int64_t imm = GetBranchImm(last.inst);
      uint64_t target = last.offset + 4 + (imm * 4);
      auto tgt_it = cfg.offset_to_block.find(target);
      if (tgt_it != cfg.offset_to_block.end())
        bb.successors.push_back(tgt_it->second);
      uint64_t fallthrough = last.offset + last.size;
      auto ft_it = cfg.offset_to_block.find(fallthrough);
      if (ft_it != cfg.offset_to_block.end())
        bb.successors.push_back(ft_it->second);
    } else {
      if (bi + 1 < static_cast<int>(cfg.blocks.size()))
        bb.successors.push_back(bi + 1);
    }
  }

  for (int bi = 0; bi < static_cast<int>(cfg.blocks.size()); ++bi) {
    for (int succ : cfg.blocks[bi].successors) {
      if (succ >= 0 && succ < static_cast<int>(cfg.blocks.size()))
        cfg.blocks[succ].predecessors.push_back(bi);
    }
  }

  return cfg;
}

// ── Backward liveness analysis ───────────────────────────────────────────────

LivenessInfo ComputeLiveness(
    const std::vector<InternalDecodedInst> &decoded,
    const CFG &cfg,
    const llvm::MCInstrInfo &MCII,
    const llvm::MCRegisterInfo &MRI) {
  size_t n_inst = decoded.size();
  LivenessInfo info;
  info.live_before.assign(n_inst, llvm::BitVector(256));
  info.live_after.assign(n_inst, llvm::BitVector(256));

  size_t n_blocks = cfg.blocks.size();
  if (n_blocks == 0) return info;

  std::vector<llvm::BitVector> bb_live_in(n_blocks, llvm::BitVector(256));
  std::vector<llvm::BitVector> bb_live_out(n_blocks, llvm::BitVector(256));

  bool changed = true;
  int max_iters = 200;
  while (changed && max_iters-- > 0) {
    changed = false;
    for (int bi = static_cast<int>(n_blocks) - 1; bi >= 0; --bi) {
      const auto &bb = cfg.blocks[bi];
      if (bb.inst_indices.empty()) continue;

      llvm::BitVector new_live_out(256);
      size_t last_idx = bb.inst_indices.back();
      const auto &last = decoded[last_idx];
      if (last.mnemonic.find("s_setpc") == 0 ||
          last.mnemonic.find("s_swappc") == 0) {
        new_live_out.set(0, 256);
      } else {
        for (int succ : bb.successors) {
          if (succ >= 0 && succ < static_cast<int>(n_blocks))
            new_live_out |= bb_live_in[succ];
        }
      }

      llvm::BitVector live = new_live_out;
      for (int ii = static_cast<int>(bb.inst_indices.size()) - 1;
           ii >= 0; --ii) {
        size_t inst_idx = bb.inst_indices[ii];
        RegDefUse du = GetInstRegDefUse(decoded[inst_idx].inst, MCII, MRI);
        live.reset(du.defs);
        live |= du.uses;
      }

      if (live != bb_live_in[bi]) {
        bb_live_in[bi] = std::move(live);
        changed = true;
      }
      if (new_live_out != bb_live_out[bi]) {
        bb_live_out[bi] = std::move(new_live_out);
        changed = true;
      }
    }
  }

  info.converged = !changed;

  for (int bi = 0; bi < static_cast<int>(n_blocks); ++bi) {
    const auto &bb = cfg.blocks[bi];
    if (bb.inst_indices.empty()) continue;

    llvm::BitVector live = bb_live_out[bi];
    for (int ii = static_cast<int>(bb.inst_indices.size()) - 1;
         ii >= 0; --ii) {
      size_t inst_idx = bb.inst_indices[ii];
      info.live_after[inst_idx] = live;
      RegDefUse du = GetInstRegDefUse(decoded[inst_idx].inst, MCII, MRI);
      live.reset(du.defs);
      live |= du.uses;
      info.live_before[inst_idx] = live;
    }
  }

  return info;
}

// ── GetKernelVgprCount ───────────────────────────────────────────────────────

int GetKernelVgprCount(const uint8_t *elf_data, size_t elf_size,
                              const ElfInfo &elf_info,
                              const std::string &kernel_name) {
  std::string kd_name = kernel_name + ".kd";
  for (const auto &sym : elf_info.symbols) {
    if (sym.name != kd_name) continue;
    if (sym.shndx >= elf_info.sections.size()) continue;
    const auto &sec = elf_info.sections[sym.shndx];
    if (sym.value < sec.addr) continue;
    uint64_t kd_file_offset = sec.offset + (sym.value - sec.addr);
    if (kd_file_offset + 64 > elf_size) continue;
    uint32_t rsrc1;
    std::memcpy(&rsrc1, elf_data + kd_file_offset + 48, 4);
    uint32_t granulated = rsrc1 & KD_RSRC1_VGPR_MASK;
    return static_cast<int>((granulated + 1) * 8);
  }
  return 256;
}

// ── Post-patch verification ──────────────────────────────────────────────────

[[nodiscard]] bool VerifyPatchCorrectness(
    const uint8_t *text, uint64_t text_size,
    const LLVMState &llvm_state,
    const std::vector<ScratchPatchInfo> &scratch_patches) {
  if (scratch_patches.empty()) return true;

  std::vector<InternalDecodedInst> decoded;
  if (!DecodeTextSection(text, text_size, llvm_state, decoded)) return true;

  CFG cfg = BuildCFG(decoded, *llvm_state.MCII);
  LivenessInfo liveness = ComputeLiveness(decoded, cfg,
                                          *llvm_state.MCII, *llvm_state.MRI);

  std::unordered_map<uint64_t, size_t> offset_to_idx;
  for (size_t i = 0; i < decoded.size(); ++i)
    offset_to_idx[decoded[i].offset] = i;

  bool clean = true;
  for (const auto &sp : scratch_patches) {
    auto it = offset_to_idx.find(sp.offset);
    if (it == offset_to_idx.end()) continue;
    size_t idx = it->second;
    if (idx >= liveness.live_before.size()) continue;

    for (int reg = sp.scratch_regs.find_first(); reg != -1;
         reg = sp.scratch_regs.find_next(reg)) {
      if (liveness.live_before[idx].test(reg)) {
        HotswapLog(HotswapLogLevel::Error) << "hotswap: WARNING: scratch v" << reg
                  << " is live at patch point 0x" << std::hex << sp.offset
                  << std::dec << " in post-patch verification\n";
        clean = false;
      }
    }
  }
  return clean;
}
