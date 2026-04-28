//===- comgr-hotswap-transpiler-helpers.cpp - Transpiler utility functions -===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

// ── ISA-family predicates ────────────────────────────────────────────────────

namespace COMGR {
namespace hotswap {

bool isGfx9Target(llvm::StringRef Cpu) {
  return Cpu.starts_with("gfx9");
}

bool isGfx12Target(llvm::StringRef Cpu) {
  return Cpu.starts_with("gfx12");
}

} // namespace hotswap
} // namespace COMGR

// ── Wave32→Wave64 EXEC Patterns ─────────────────────────────────────────────

bool WritesExecLo(const std::string& line) {
  size_t mnem_end = line.find_first_of(" \t");
  if (mnem_end == std::string::npos) return false;
  size_t op_start = line.find_first_not_of(" \t,", mnem_end);
  if (op_start == std::string::npos) return false;
  if (line.compare(op_start, 7, "exec_lo") == 0) return true;
  std::string mnemonic = line.substr(0, mnem_end);
  if (mnemonic.find("saveexec_b32") != std::string::npos) return true;
  return false;
}

// ── Wait Counter Translation ─────────────────────────────────────────────────

// LEGACY: String-based classification used by text-based handler dispatch.
// Will be replaced by opcode checks when handlers are migrated to MCInst.
bool IsWaitInstruction(const std::string& mnemonic) {
  return mnemonic == "s_wait_loadcnt" || mnemonic == "s_wait_storecnt" ||
         mnemonic == "s_wait_samplecnt" || mnemonic == "s_wait_bvhcnt" ||
         mnemonic == "s_wait_expcnt" || mnemonic == "s_wait_dscnt" ||
         mnemonic == "s_wait_kmcnt" || mnemonic == "s_wait_loadcnt_dscnt" ||
         mnemonic == "s_wait_storecnt_dscnt" || mnemonic == "s_wait_xcnt" ||
         mnemonic == "s_wait_asynccnt" || mnemonic == "s_wait_tensorcnt";
}

std::string TranslateWaitInstruction(const std::string& line) {
  std::string mnemonic;
  int count = 0;
  std::istringstream iss(line);
  iss >> mnemonic >> count;
  if (iss.fail()) count = 0;

  if (mnemonic == "s_wait_loadcnt" || mnemonic == "s_wait_samplecnt" ||
      mnemonic == "s_wait_bvhcnt" || mnemonic == "s_wait_storecnt")
    return "s_waitcnt vmcnt(" + std::to_string(count) + ")";
  if (mnemonic == "s_wait_dscnt" || mnemonic == "s_wait_kmcnt")
    return "s_waitcnt lgkmcnt(" + std::to_string(count) + ")";
  if (mnemonic == "s_wait_expcnt")
    return "s_waitcnt expcnt(" + std::to_string(count) + ")";
  if (mnemonic == "s_wait_loadcnt_dscnt")
    return "s_waitcnt vmcnt(" + std::to_string(count) +
           ") lgkmcnt(" + std::to_string(count) + ")";
  if (mnemonic == "s_wait_storecnt_dscnt")
    return "s_waitcnt vmcnt(" + std::to_string(count) +
           ") lgkmcnt(" + std::to_string(count) + ")";
  return "s_waitcnt vmcnt(0) lgkmcnt(0) expcnt(0)";
}

// ── Unsupported Instruction Detection ────────────────────────────────────────

// LEGACY: String-based classification used by text-based handler dispatch.
// Will be replaced by TSFlags/opcode checks when handlers are migrated to MCInst.
bool IsUnsupportedOnGFX9(const std::string& mnemonic) {
  if (mnemonic.find("tensor_") == 0) return true;
  if (mnemonic.find("cluster_") == 0) return true;
  if (mnemonic.find("_prefetch_") != std::string::npos) return true;
  if (mnemonic.find("v_permlane16") == 0) return true;
  if (mnemonic.find("v_permlanex16") == 0) return true;
  if (mnemonic == "s_wait_alu") return true;
  if (mnemonic == "s_delay_alu") return true;
  if (mnemonic == "s_set_vgpr_msb") return true;
  if (mnemonic == "s_code_end") return true;
  return false;
}

// ── VCC Register Width Translation ───────────────────────────────────────────

std::string WidenVccReferences(const std::string& line) {
  std::string result = line;
  size_t mnem_end = result.find_first_of(" \t");
  if (mnem_end == std::string::npos) return result;
  std::string operands = result.substr(mnem_end);
  size_t pos = 0;
  while ((pos = operands.find("vcc_lo", pos)) != std::string::npos) {
    size_t end = pos + 6;
    if (end < operands.size() && (std::isalnum(operands[end]) || operands[end] == '_')) {
      pos = end;
      continue;
    }
    operands.replace(pos, 6, "vcc");
    pos += 3;
  }
  return result.substr(0, mnem_end) + operands;
}

// ── EXEC Width Widening ──────────────────────────────────────────────────────

std::vector<std::string> WidenExecOperation(const std::string& line, bool compact_mode, int cmpx_temp_sgpr, const CondMaskContext *cond_ctx) {
  std::vector<std::string> result;
  std::string mnemonic = line.substr(0, line.find_first_of(" \t"));

  // saveexec_b32 is now handled in TranslateInstruction (handlers.cpp)
  // which has access to scratch SGPRs for proper exec_hi save/restore.
  // If we reach here, it's a saveexec that wasn't caught — passthrough.
  if (mnemonic.find("saveexec_b32") != std::string::npos) {
    result.push_back(line);
    return result;
  }

  // For s_mov_b32 exec_lo, sN → also restore exec_hi from scratch.
  // exec_hi was saved to cmpx_temp_sgpr+2 by the saveexec handler.
  // For s_mov_b32 sN, exec_lo → also save exec_hi to sN|1.
  // This handles the pattern where wave32 code saves exec before v_cmpx.
  if (mnemonic == "s_mov_b32" && cmpx_temp_sgpr >= 0) {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() == 2) {
      std::string dst = operands[0], src = operands[1];
      auto trim = [](std::string& s) {
        size_t a = s.find_first_not_of(" \t");
        size_t b = s.find_last_not_of(" \t");
        if (a != std::string::npos) s = s.substr(a, b - a + 1);
      };
      trim(dst); trim(src);

      // Case 1: s_mov_b32 exec_lo, sN → restore exec_hi from per-SGPR scratch
      if (dst == "exec_lo") {
        result.push_back(line);
        // Find the per-SGPR scratch for the source register.
        std::string exec_hi_src = "s" + std::to_string(cmpx_temp_sgpr + 2); // fallback
        if (!src.empty() && src[0] == 's' && src.size() > 1 &&
            std::isdigit((unsigned char)src[1]) && src.find('[') == std::string::npos) {
          size_t nend = 1;
          while (nend < src.size() && std::isdigit((unsigned char)src[nend])) nend++;
          int src_reg = std::stoi(src.substr(1, nend - 1));
          if (cond_ctx) {
            auto it = cond_ctx->cond_hi_scratch.find(src_reg);
            if (it != cond_ctx->cond_hi_scratch.end())
              exec_hi_src = "s" + std::to_string(it->second);
            else
              exec_hi_src = "s" + std::to_string(src_reg | 1);
          } else {
            exec_hi_src = "s" + std::to_string(src_reg | 1);
          }
        }
        result.push_back("s_mov_b32 exec_hi, " + exec_hi_src);
        return result;
      }
      // Case 2: s_mov_b32 sN, exec_lo → save exec_hi to per-SGPR scratch.
      // This handles the pattern where wave32 code saves exec before v_cmpx.
      if (src == "exec_lo" && !dst.empty() && dst[0] == 's' &&
          dst.size() > 1 && std::isdigit((unsigned char)dst[1]) &&
          dst.find('[') == std::string::npos) {
        result.push_back(line);
        // Use per-SGPR scratch from unified hi-scratch map if available.
        size_t nend = 1;
        while (nend < dst.size() && std::isdigit((unsigned char)dst[nend])) nend++;
        int dst_reg = std::stoi(dst.substr(1, nend - 1));
        int exec_hi_dst = dst_reg | 1; // default: natural pair
        if (cond_ctx) {
          auto it = cond_ctx->cond_hi_scratch.find(dst_reg);
          if (it != cond_ctx->cond_hi_scratch.end())
            exec_hi_dst = it->second;
        }
        result.push_back("s_mov_b32 s" + std::to_string(exec_hi_dst) + ", exec_hi");
        return result;
      }
    }
  }

  // Widen s_*_b32 exec_lo, exec_lo, <src> → also apply to exec_hi
  // Handles s_and_b32, s_or_b32, s_andn2_b32, s_xor_b32 with exec_lo as dest
  if ((mnemonic == "s_and_b32" || mnemonic == "s_or_b32" ||
       mnemonic == "s_andn2_b32" || mnemonic == "s_xor_b32") &&
      line.find("exec_lo") != std::string::npos) {
    // Parse: mnemonic exec_lo, src1, src2
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() == 3 && operands[0].find("exec_lo") != std::string::npos) {
      result.push_back(line);
      // Build matching exec_hi instruction
      auto widenOp = [cmpx_temp_sgpr, cond_ctx](const std::string& op) -> std::string {
        std::string s = op;
        size_t ts = s.find_first_not_of(" \t");
        if (ts != std::string::npos) s = s.substr(ts);
        if (s == "exec_lo") return "exec_hi";
        if (s == "vcc_lo" || s == "vcc") return "vcc_hi";
        // Single SGPR sN → hi half from unified scratch map.
        if (!s.empty() && s[0] == 's' && s.size() > 1 &&
            std::isdigit((unsigned char)s[1]) && s.find('[') == std::string::npos) {
          size_t nend = 1;
          while (nend < s.size() && std::isdigit((unsigned char)s[nend])) nend++;
          int regnum = std::stoi(s.substr(1, nend - 1));
          // Look up unified hi-scratch map for this SGPR.
          // For odd v_cmp dests, hi is in even partner's scratch.
          if (cond_ctx) {
            if ((regnum & 1) && cond_ctx->vcmp_odd_dests.count(regnum)) {
              auto it = cond_ctx->cond_hi_scratch.find(regnum & ~1);
              if (it != cond_ctx->cond_hi_scratch.end())
                return "s" + std::to_string(it->second);
            }
            auto it = cond_ctx->cond_hi_scratch.find(regnum);
            if (it != cond_ctx->cond_hi_scratch.end())
              return "s" + std::to_string(it->second);
          }
          int hi_reg = regnum | 1;
          if (hi_reg == regnum && cmpx_temp_sgpr >= 0) {
            // Odd SGPR without scratch: likely a saved exec_lo
            // from saveexec_b32. Use exec_hi_save register.
            return "s" + std::to_string(cmpx_temp_sgpr + 2);
          }
          return "s" + std::to_string(hi_reg);
        }
        // SGPR pair s[N:N+1] → use hi register
        if (s.find("s[") == 0) {
          size_t colon = s.find(':');
          size_t close = s.find(']');
          if (colon != std::string::npos && close != std::string::npos)
            return "s" + s.substr(colon + 1, close - colon - 1);
        }
        return s;
      };
      std::string hi_src1 = widenOp(operands[1]);
      std::string hi_src2 = widenOp(operands[2]);
      result.push_back(mnemonic + " exec_hi, " + hi_src1 + ", " + hi_src2);
      return result;
    }
  }

  // Widen s_or_b64 exec, exec, s[N:N+1] and similar — passthrough since
  // they already operate on 64-bit exec. BUT if the source is s[N:N+1] and
  // the exec_hi was saved to scratch, the lo half of the pair may be wrong.
  // For now, trust that the compiler's s[N:N+1] pair is correctly populated
  // by our saveexec handler.

  result.push_back(line);
  return result;
}

// ── Operand Syntax Translation ───────────────────────────────────────────────

std::string TranslateOperandSyntax(const std::string& line,
                                           const std::string& mnemonic) {
  (void)mnemonic;
  std::string result = line;
  {
    size_t pos = result.find("scope:");
    if (pos != std::string::npos) {
      size_t end = result.find_first_of(" \t,", pos);
      if (end == std::string::npos) end = result.size();
      result.erase(pos, end - pos);
    }
  }
  {
    size_t pos = result.find("th:");
    if (pos != std::string::npos) {
      size_t end = result.find_first_of(" \t,", pos);
      if (end == std::string::npos) end = result.size();
      std::string th_value = result.substr(pos, end - pos);
      if (th_value.find("TH_ATOMIC_RETURN") != std::string::npos)
        result.replace(pos, end - pos, "sc0");
      else
        result.erase(pos, end - pos);
    }
  }
  {
    size_t pos = result.find(" nv");
    while (pos != std::string::npos) {
      size_t end = pos + 3;
      if (end >= result.size() || result[end] == ' ' || result[end] == '\t' ||
          result[end] == ',' || result[end] == '\0') {
        result.erase(pos, end - pos);
      } else {
        pos = result.find(" nv", pos + 1);
        continue;
      }
      pos = result.find(" nv", pos);
    }
  }
  {
    size_t pos = result.find("scale_offset");
    if (pos != std::string::npos) {
      size_t end = pos + 12;
      if (pos > 0 && (result[pos-1] == ' ' || result[pos-1] == ',')) --pos;
      result.erase(pos, end - pos);
    }
  }
  // Replace 'null' operand with '0' in buffer instructions (GFX9 doesn't support null soffset)
  if (mnemonic.find("buffer_") == 0) {
    size_t pos = result.find(", null");
    while (pos != std::string::npos) {
      size_t after = pos + 6;
      if (after >= result.size() || result[after] == ' ' || result[after] == '\t' ||
          result[after] == ',' || result[after] == '\0') {
        result.replace(pos, 6, ", 0");
        pos = result.find(", null", pos + 3);
      } else {
        pos = result.find(", null", pos + 1);
      }
    }
  }
  // Strip .l/.h subregister suffixes on VGPR operands (GFX12 f16 sub-word, not on GFX9)
  {
    size_t pos = 0;
    while (pos < result.size()) {
      // Look for v<N>.l or v<N>.h patterns
      if (result[pos] == 'v' && pos + 1 < result.size() && std::isdigit(result[pos + 1])) {
        // Skip past the register number
        size_t numstart = pos + 1;
        size_t numend = numstart;
        while (numend < result.size() && std::isdigit(result[numend])) numend++;
        if (numend + 1 < result.size() && result[numend] == '.' &&
            (result[numend + 1] == 'l' || result[numend + 1] == 'h')) {
          // Check that next char after .l/.h is not alphanumeric
          size_t suffend = numend + 2;
          if (suffend >= result.size() || !std::isalnum(result[suffend])) {
            result.erase(numend, 2);
            continue;
          }
        }
      }
      pos++;
    }
  }
  // GFX12 src_flat_scratch_base → GFX9 flat_scratch
  {
    // For 64-bit moves (s_mov_b64), use flat_scratch (the 64-bit pair register)
    if (mnemonic == "s_mov_b64") {
      size_t pos = result.find("src_flat_scratch_base_lo");
      if (pos != std::string::npos)
        result.replace(pos, 24, "flat_scratch");
    } else {
      size_t pos = result.find("src_flat_scratch_base_lo");
      if (pos != std::string::npos)
        result.replace(pos, 24, "flat_scratch_lo");
      pos = result.find("src_flat_scratch_base_hi");
      if (pos != std::string::npos)
        result.replace(pos, 24, "flat_scratch_hi");
    }
  }
  // Strip HW_REG_WAVE_SCHED_MODE setreg instructions (not on GFX9)
  if (mnemonic == "s_setreg_imm32_b32" || mnemonic == "s_setreg_b32") {
    if (result.find("HW_REG_WAVE_SCHED_MODE") != std::string::npos)
      return "s_nop 0 ; UNSUPPORTED: " + mnemonic + " HW_REG_WAVE_SCHED_MODE";
  }
  while (!result.empty() && (result.back() == ' ' || result.back() == '\t' ||
                              result.back() == ','))
    result.pop_back();
  return result;
}

// ── Extract/Replace Mnemonic ─────────────────────────────────────────────────

std::string TranspileExtractMnemonic(const std::string& line) {
  size_t start = line.find_first_not_of(" \t");
  if (start == std::string::npos) return "";
  size_t end = line.find_first_of(" \t", start);
  if (end == std::string::npos) return line.substr(start);
  return line.substr(start, end - start);
}

std::string TranspileReplaceMnemonic(const std::string& line,
                                             const std::string& old_mnemonic,
                                             const std::string& new_mnemonic) {
  size_t pos = line.find(old_mnemonic);
  if (pos == std::string::npos) return line;
  std::string result = line;
  result.replace(pos, old_mnemonic.size(), new_mnemonic);
  return result;
}

// ── TTMP Taint Analysis ──────────────────────────────────────────────────────

RegKind ClassifyReg(unsigned reg, const llvm::MCRegisterInfo& MRI) {
  const char* name = MRI.getName(reg);
  if (!name) return RegKind::Other;
  if (strncmp(name, "TTMP", 4) == 0) return RegKind::TTMP;
  if (strncmp(name, "SGPR", 4) == 0) return RegKind::SGPR;
  if (strncmp(name, "VGPR", 4) == 0) return RegKind::VGPR;
  if (strcmp(name, "SCC") == 0) return RegKind::SCC;
  if (strncmp(name, "VCC", 3) == 0) return RegKind::VCC;
  if (strncmp(name, "EXEC", 4) == 0) return RegKind::EXEC;
  return RegKind::Other;
}

bool IsRegTainted(unsigned reg, const std::set<unsigned>& tainted,
                         const llvm::MCRegisterInfo& MRI) {
  if (tainted.count(reg)) return true;
  for (auto sub : MRI.subregs(reg))
    if (tainted.count(sub)) return true;
  for (auto sup : MRI.superregs(reg))
    if (tainted.count(sup)) return true;
  return false;
}

void TaintReg(unsigned reg, std::set<unsigned>& tainted,
                     const llvm::MCRegisterInfo& MRI) {
  tainted.insert(reg);
  for (auto sub : MRI.subregs(reg))
    tainted.insert(sub);
}

void UntaintReg(unsigned reg, std::set<unsigned>& tainted,
                       const llvm::MCRegisterInfo& MRI) {
  tainted.erase(reg);
  for (auto sub : MRI.subregs(reg))
    tainted.erase(sub);
  for (auto sup : MRI.superregs(reg))
    tainted.erase(sup);
}

void GetInstRegs(const llvm::MCInst& inst,
                        const llvm::MCInstrInfo& MCII,
                        const llvm::MCRegisterInfo& MRI,
                        std::vector<unsigned>& defs,
                        std::vector<unsigned>& uses) {
  (void)MRI;
  const llvm::MCInstrDesc& desc = MCII.get(inst.getOpcode());
  unsigned num_defs = desc.getNumDefs();
  for (unsigned i = 0; i < inst.getNumOperands(); ++i) {
    const auto& op = inst.getOperand(i);
    if (!op.isReg() || op.getReg() == 0) continue;
    if (i < num_defs)
      defs.push_back(op.getReg());
    else
      uses.push_back(op.getReg());
  }
  for (auto imp : desc.implicit_defs())
    defs.push_back(imp);
  for (auto imp : desc.implicit_uses())
    uses.push_back(imp);
}

std::vector<TaintResult> AnalyzeTTMPTaint(
    const std::vector<SourceInstrForTaint>& instrs,
    const llvm::MCInstrInfo& MCII,
    const llvm::MCRegisterInfo& MRI) {

  std::vector<TaintResult> results;
  results.reserve(instrs.size());
  std::set<unsigned> tainted;
  bool dump = std::getenv("HSA_HOTSWAP_DUMP") != nullptr;

  for (size_t i = 0; i < instrs.size(); ++i) {
    const auto& si = instrs[i];
    const auto& text = si.text;
    std::string mnemonic = TranspileExtractMnemonic(text);

    TaintResult tr;
    tr.action = TaintAction::Keep;

    if (!si.valid_inst) {
      results.push_back(tr);
      continue;
    }

    if (mnemonic.empty() || mnemonic[0] != 's' ||
        mnemonic.find("s_cbranch_") == 0 || mnemonic == "s_branch" ||
        mnemonic == "s_endpgm" || mnemonic == "s_barrier" ||
        mnemonic.find("s_barrier_") == 0 || mnemonic == "s_nop" ||
        mnemonic == "s_waitcnt" || mnemonic.find("s_wait_") == 0 ||
        mnemonic == "s_clause" || mnemonic == "s_delay_alu" ||
        mnemonic == "s_wait_alu" || mnemonic == "s_code_end" ||
        mnemonic == "s_set_inst_prefetch_distance") {
      results.push_back(tr);
      continue;
    }

    std::vector<unsigned> defs, uses;
    GetInstRegs(si.inst, MCII, MRI, defs, uses);

    bool uses_ttmp = false;
    for (auto r : uses)
      if (ClassifyReg(r, MRI) == RegKind::TTMP) { uses_ttmp = true; break; }
    bool defs_ttmp = false;
    for (auto r : defs)
      if (ClassifyReg(r, MRI) == RegKind::TTMP) { defs_ttmp = true; break; }

    if (mnemonic == "s_getreg_b32" &&
        text.find("HW_REG_IB_STS2") != std::string::npos) {
      tr.action = TaintAction::Skip;
      for (auto r : defs) TaintReg(r, tainted, MRI);
      if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: SKIP (HW_REG_IB_STS2): " << text << "\n";
      results.push_back(tr);
      continue;
    }

    if ((mnemonic == "s_setreg_imm32_b32" || mnemonic == "s_setreg_b32") &&
        text.find("HW_REG_WAVE_MODE") != std::string::npos) {
      tr.action = TaintAction::Skip;
      if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: SKIP (HW_REG_WAVE_MODE): " << text << "\n";
      results.push_back(tr);
      continue;
    }

    if (uses_ttmp || defs_ttmp) {
      if (mnemonic == "s_cselect_b32") {
        tr.action = TaintAction::Replace;
        size_t op_start = text.find(mnemonic) + mnemonic.size();
        std::string ops = text.substr(op_start);
        size_t s = ops.find_first_not_of(" \t");
        size_t e = ops.find_first_of(" \t,", s);
        if (s != std::string::npos)
          tr.replace_dst = ops.substr(s, e != std::string::npos ? e - s : std::string::npos);
        tr.replace_src = (text.find("ttmp9") != std::string::npos) ? "v5" : "v4";
        for (auto r : defs) UntaintReg(r, tainted, MRI);
        for (auto r : uses) {
          if (ClassifyReg(r, MRI) == RegKind::SCC)
            UntaintReg(r, tainted, MRI);
        }
        if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: REPLACE (s_cselect ttmp → "
                            << tr.replace_dst << " = " << tr.replace_src << "): " << text << "\n";
      } else {
        tr.action = TaintAction::Skip;
        for (auto r : defs) {
          RegKind kind = ClassifyReg(r, MRI);
          if (kind == RegKind::SGPR || kind == RegKind::SCC)
            TaintReg(r, tainted, MRI);
        }
        if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: SKIP (direct TTMP): " << text << "\n";
      }
      results.push_back(tr);
      continue;
    }

    if (mnemonic.find("s_load_") == 0 || mnemonic.find("s_buffer_load_") == 0) {
      for (auto r : defs) UntaintReg(r, tainted, MRI);
      if (dump && !tainted.empty())
        HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: KEEP (s_load clears taint on defs): " << text << "\n";
      results.push_back(tr);
      continue;
    }

    if (mnemonic.find("s_cmp_") == 0) {
      bool any_tainted = false;
      for (auto r : uses)
        if (IsRegTainted(r, tainted, MRI)) { any_tainted = true; break; }
      if (any_tainted) {
        tr.action = TaintAction::Skip;
        for (auto r : defs) TaintReg(r, tainted, MRI);
        if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: SKIP (s_cmp tainted): " << text << "\n";
        results.push_back(tr);
        continue;
      }
      results.push_back(tr);
      continue;
    }

    bool has_tainted_src = false;
    bool has_untainted_sgpr_src = false;
    for (auto r : uses) {
      RegKind kind = ClassifyReg(r, MRI);
      if (kind == RegKind::SGPR || kind == RegKind::SCC) {
        if (IsRegTainted(r, tainted, MRI))
          has_tainted_src = true;
        else
          has_untainted_sgpr_src = true;
      }
    }

    if (has_tainted_src && !has_untainted_sgpr_src) {
      tr.action = TaintAction::Skip;
      for (auto r : defs) {
        RegKind kind = ClassifyReg(r, MRI);
        if (kind == RegKind::SGPR || kind == RegKind::SCC)
          TaintReg(r, tainted, MRI);
      }
      if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: SKIP (all srcs tainted): " << text << "\n";
      results.push_back(tr);
      continue;
    }

    if (has_tainted_src && has_untainted_sgpr_src) {
      for (auto r : defs) UntaintReg(r, tainted, MRI);
      if (dump) HotswapLog(HotswapLogLevel::Debug) << "hotswap: taint: KEEP (mixed taint, clear defs): " << text << "\n";
      results.push_back(tr);
      continue;
    }

    if (!tainted.empty()) {
      for (auto r : defs) UntaintReg(r, tainted, MRI);
    }
    results.push_back(tr);
  }

  return results;
}

// ── Operand parsing helper ───────────────────────────────────────────────────

std::vector<std::string> ParseOperandList(const std::string& line,
                                                  const std::string& mnemonic) {
  std::string ops = line.substr(line.find(mnemonic) + mnemonic.size());
  size_t op_start = ops.find_first_not_of(" \t");
  if (op_start != std::string::npos) ops = ops.substr(op_start);
  std::vector<std::string> operands;
  std::istringstream oss(ops);
  std::string tok;
  while (std::getline(oss, tok, ',')) {
    size_t s = tok.find_first_not_of(" \t");
    size_t e = tok.find_last_not_of(" \t");
    if (s != std::string::npos)
      operands.push_back(tok.substr(s, e - s + 1));
  }
  return operands;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ELF utility functions (transpiler pipeline)
// ═══════════════════════════════════════════════════════════════════════════════

std::string ExtractCPU(const std::string &isa_name) {
  size_t pos = isa_name.rfind("gfx");
  if (pos != std::string::npos) {
    std::string cpu;
    for (size_t i = pos; i < isa_name.size(); ++i) {
      char c = isa_name[i];
      if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          (c >= 'A' && c <= 'Z'))
        cpu += c;
      else
        break;
    }
    return cpu;
  }
  return "";
}

[[nodiscard]] bool ParseElfInfo(const uint8_t *elf, size_t elf_size,
                                ElfInfo &info) {
  using ELFT = llvm::object::ELF64LE;
  auto elf_or_err = llvm::object::ELFFile<ELFT>::create(
      llvm::StringRef(reinterpret_cast<const char *>(elf), elf_size));
  if (!elf_or_err) {
    llvm::consumeError(elf_or_err.takeError());
    return false;
  }
  const auto &elf_file = *elf_or_err;

  auto sections_or_err = elf_file.sections();
  if (!sections_or_err) {
    llvm::consumeError(sections_or_err.takeError());
    return false;
  }
  auto shdrs = *sections_or_err;

  for (const auto &shdr : shdrs) {
    ElfSection sec;
    sec.type = shdr.sh_type;
    sec.offset = shdr.sh_offset;
    sec.size = shdr.sh_size;
    sec.addr = shdr.sh_addr;
    sec.name_idx = shdr.sh_name;

    auto name_or_err = elf_file.getSectionName(shdr);
    if (name_or_err)
      sec.name = name_or_err->str();
    else
      llvm::consumeError(name_or_err.takeError());

    if (sec.name == ".text" && sec.offset + sec.size <= elf_size) {
      info.text_section_idx = static_cast<int>(info.sections.size());
      info.text_idx = info.text_section_idx;
      info.text_offset = sec.offset;
      info.text_size = sec.size;
      info.text_addr = sec.addr;
    }

    info.sections.push_back(std::move(sec));
  }

  size_t num_sections = info.sections.size();
  for (size_t i = 0; i < num_sections; ++i) {
    if (info.sections[i].type != 2 && info.sections[i].type != 11)
      continue;

    const auto &sym_shdr = *(shdrs.begin() + i);

    auto syms_or_err = elf_file.symbols(&sym_shdr);
    if (!syms_or_err) {
      llvm::consumeError(syms_or_err.takeError());
      continue;
    }

    auto strtab_or_err = elf_file.getStringTableForSymtab(sym_shdr, shdrs);
    if (!strtab_or_err) {
      llvm::consumeError(strtab_or_err.takeError());
      continue;
    }

    for (const auto &sym : *syms_or_err) {
      ElfSymbol esym;
      esym.info = sym.st_info;
      esym.shndx = sym.st_shndx;
      esym.value = sym.st_value;
      esym.size = sym.st_size;

      auto sym_name_or_err = sym.getName(*strtab_or_err);
      if (sym_name_or_err)
        esym.name = sym_name_or_err->str();
      else
        llvm::consumeError(sym_name_or_err.takeError());

      info.symbols.push_back(std::move(esym));
    }
  }

  return info.text_section_idx >= 0;
}

std::string FindKernelAtOffset(const ElfInfo &elf_info,
                               uint64_t text_offset) {
  for (auto &sym : elf_info.symbols) {
    uint8_t sym_type = sym.info & 0xf;
    if (sym_type != 2 && sym_type != 10)
      continue;
    if (sym.shndx != static_cast<uint16_t>(elf_info.text_section_idx))
      continue;
    uint64_t sym_start = sym.value;
    uint64_t sym_end = sym.value + sym.size;
    if (text_offset >= sym_start && text_offset < sym_end)
      return sym.name;
  }
  return "";
}

// ═══════════════════════════════════════════════════════════════════════════════
// LLVM MC infrastructure (transpiler pipeline)
// ═══════════════════════════════════════════════════════════════════════════════

namespace {
std::once_flag g_llvm_init_flag;
std::mutex g_target_cache_mutex;
const llvm::Target *g_cached_target = nullptr;
} // namespace

static void InitLLVMTargets() {
  COMGR::ensureLLVMInitialized();
}

LLVMState InitLLVMImpl(const std::string &isa_name,
                       const llvm::Target *cached_target) {
  std::call_once(g_llvm_init_flag, InitLLVMTargets);

  LLVMState state;
  state.cpu = ExtractCPU(isa_name);
  if (state.cpu.empty()) return state;

  llvm::Triple triple("amdgcn-amd-amdhsa");

  if (cached_target) {
    state.target = cached_target;
  } else {
    std::string error;
    state.target = llvm::TargetRegistry::lookupTarget("amdgcn", triple, error);
  }
  if (!state.target) return state;

  state.MRI.reset(
      state.target->createMCRegInfo(llvm::Triple("amdgcn-amd-amdhsa")));
  if (!state.MRI) return state;

  llvm::MCTargetOptions mc_opts;
  state.MAI.reset(state.target->createMCAsmInfo(
      *state.MRI, llvm::Triple("amdgcn-amd-amdhsa"), mc_opts));
  if (!state.MAI) return state;

  state.MCII.reset(state.target->createMCInstrInfo());
  if (!state.MCII) return state;

  state.STI.reset(state.target->createMCSubtargetInfo(
      llvm::Triple("amdgcn-amd-amdhsa"), state.cpu, ""));
  if (!state.STI || !state.STI->isCPUStringValid(state.cpu)) return state;

  state.Ctx = std::make_unique<llvm::MCContext>(triple, state.MAI.get(),
                                                state.MRI.get(),
                                                state.STI.get());
  state.MOFI = std::make_unique<llvm::MCObjectFileInfo>();
  state.MOFI->initMCObjectFileInfo(*state.Ctx, false);
  state.Ctx->setObjectFileInfo(state.MOFI.get());

  state.disasm.reset(
      state.target->createMCDisassembler(*state.STI, *state.Ctx));
  if (!state.disasm) return state;

  unsigned asm_variant = state.MAI->getAssemblerDialect();
  state.printer.reset(state.target->createMCInstPrinter(
      triple, asm_variant, *state.MAI, *state.MCII, *state.MRI));

  state.CE = state.target->createMCCodeEmitter(*state.MCII, *state.Ctx);

  state.valid = true;
  return state;
}

LLVMState InitLLVMCached(const std::string &isa_name) {
  std::call_once(g_llvm_init_flag, InitLLVMTargets);

  const llvm::Target *tgt;
  {
    std::lock_guard<std::mutex> lock(g_target_cache_mutex);
    if (!g_cached_target) {
      std::string error;
      llvm::Triple triple("amdgcn-amd-amdhsa");
      g_cached_target =
          llvm::TargetRegistry::lookupTarget("amdgcn", triple, error);
    }
    tgt = g_cached_target;
  }

  return InitLLVMImpl(isa_name, tgt);
}

[[nodiscard]] bool DecodeTextSection(const uint8_t *text, uint64_t text_size,
                                     const LLVMState &llvm_state,
                                     std::vector<InternalDecodedInst> &decoded) {
  uint64_t pos = 0;
  while (pos < text_size) {
    InternalDecodedInst di;
    di.offset = pos;

    llvm::ArrayRef<uint8_t> bytes(text + pos, text_size - pos);
    uint64_t inst_size = 0;

    auto status = llvm_state.disasm->getInstruction(di.inst, inst_size, bytes,
                                                    pos, llvm::nulls());

    if (status == llvm::MCDisassembler::Fail) {
      di.size = 4;
      di.mnemonic = "<unknown>";
      pos += 4;
    } else {
      di.size = static_cast<uint32_t>(inst_size);
      if (llvm_state.printer) {
        std::string str;
        llvm::raw_string_ostream rso(str);
        llvm_state.printer->printInst(&di.inst, 0, "", *llvm_state.STI, rso);
        rso.flush();
        size_t s = str.find_first_not_of(" \t");
        if (s != std::string::npos) {
          size_t e = str.find_first_of(" \t", s);
          di.mnemonic = str.substr(s, e - s);
        }
      } else {
        di.mnemonic = llvm_state.MCII->getName(di.inst.getOpcode()).str();
      }
      pos += inst_size;
    }
    decoded.push_back(std::move(di));
  }
  return true;
}

int GetVgprNum(unsigned reg, const llvm::MCRegisterInfo &MRI) {
  const char *name = MRI.getName(reg);
  if (!name) return -1;
  std::string rname(name);
  if (rname.find("VGPR") == 0) {
    size_t numstart = 4;
    size_t underscore = rname.find('_', numstart);
    std::string numstr = rname.substr(
        numstart, underscore == std::string::npos ? std::string::npos
                                                  : underscore - numstart);
    int val = -1;
    std::from_chars(numstr.data(), numstr.data() + numstr.size(), val);
    return val;
  }
  return -1;
}

std::pair<int, int> GetVgprRange(unsigned reg,
                                 const llvm::MCRegisterInfo &MRI) {
  const char *name = MRI.getName(reg);
  if (!name) return {-1, 0};
  std::string rname(name);
  if (rname.find("VGPR") != 0) return {-1, 0};
  int count = 1;
  for (char c : rname)
    if (c == '_') count++;
  size_t numstart = 4;
  size_t numend = rname.find_first_not_of("0123456789", numstart);
  if (numend == std::string::npos) numend = rname.size();
  std::string numstr = rname.substr(numstart, numend - numstart);
  int base = -1;
  auto [p, ec] = std::from_chars(numstr.data(), numstr.data() + numstr.size(),
                                 base);
  if (ec != std::errc())
    return {-1, 0};
  return {base, count};
}

