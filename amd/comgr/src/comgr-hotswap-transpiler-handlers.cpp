//===- comgr-hotswap-transpiler-handlers.cpp - Instruction translation -----===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

// ── Handler: Wait Instructions ───────────────────────────────────────────────

static TranslationResult HandleWaitInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int, int, bool) {
  if (IsWaitInstruction(mnemonic))
    return std::vector<std::string>{TranslateWaitInstruction(line)};
  if (mnemonic == "s_wait_alu" || mnemonic == "s_delay_alu" ||
      mnemonic == "s_clause" || mnemonic == "s_set_inst_prefetch_distance")
    return std::vector<std::string>{};
  return std::nullopt;
}

// ── Handler: Unsupported / Skip Instructions ─────────────────────────────────

static TranslationResult HandleUnsupportedInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int, int, bool) {
  if ((mnemonic == "s_setreg_imm32_b32" || mnemonic == "s_setreg_b32" ||
       mnemonic == "s_getreg_b32") &&
      (line.find("HW_REG_WAVE_MODE") != std::string::npos ||
       line.find("HW_REG_IB_STS2") != std::string::npos))
    return std::vector<std::string>{};
  if (line.find("ttmp6") != std::string::npos ||
      line.find("ttmp7") != std::string::npos ||
      line.find("ttmp9") != std::string::npos)
    return std::vector<std::string>{};
  if (mnemonic == "s_code_end")
    return std::vector<std::string>{};
  if (mnemonic == "s_sendmsg" && line.find("MSG_DEALLOC_VGPRS") != std::string::npos)
    return std::vector<std::string>{};
  if (mnemonic == "s_endpgm")
    return std::vector<std::string>{"s_endpgm"};
  if (mnemonic == "s_barrier_signal")
    return std::vector<std::string>{"s_barrier"};
  if (mnemonic == "s_barrier_wait")
    return std::vector<std::string>{"s_nop 0"};
  if (IsUnsupportedOnGFX9(mnemonic))
    return std::vector<std::string>{"s_nop 0 ; UNSUPPORTED: " + mnemonic};
  return std::nullopt;
}

// ── Handler: SMEM Instructions ───────────────────────────────────────────────

static TranslationResult HandleSMEMInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int, int, bool) {
  if (mnemonic != "s_load_b96") return std::nullopt;
  std::vector<std::string> result;
  auto parseSGPRRange = [](const std::string &s, int &lo, int &hi) -> bool {
    size_t start = s.find("s[");
    if (start == std::string::npos) return false;
    size_t colon = s.find(':', start + 2);
    if (colon == std::string::npos) return false;
    size_t close = s.find(']', colon + 1);
    if (close == std::string::npos) return false;
    auto r1 = std::from_chars(s.data() + start + 2, s.data() + colon, lo);
    auto r2 = std::from_chars(s.data() + colon + 1, s.data() + close, hi);
    return r1.ec == std::errc() && r2.ec == std::errc();
  };
  std::string ops_part = line.substr(line.find(mnemonic) + mnemonic.size());
  int lo = 0, hi = 0;
  if (parseSGPRRange(ops_part, lo, hi)) {
    size_t close_bracket = ops_part.find(']', ops_part.find("s["));
    std::string after_reg = ops_part.substr(close_bracket + 1);
    size_t offset_pos = after_reg.rfind("0x");
    if (offset_pos == std::string::npos) offset_pos = after_reg.rfind(' ');
    if (offset_pos != std::string::npos) {
      size_t num_start = after_reg.find_last_of(" \t,", after_reg.size()-1);
      if (num_start == std::string::npos) num_start = 0; else num_start++;
      std::string offset_str = after_reg.substr(num_start);
      int64_t offset_val = 0;
      {
        const char* ob = offset_str.data();
        const char* oe = ob + offset_str.size();
        int obase = 10;
        if (offset_str.size() > 2 && offset_str[0] == '0' &&
            (offset_str[1] == 'x' || offset_str[1] == 'X')) {
          obase = 16; ob += 2;
        }
        std::from_chars(ob, oe, offset_val, obase);
      }
      std::string base_part = after_reg.substr(0, num_start);
      size_t be = base_part.find_last_not_of(" \t,");
      if (be != std::string::npos) base_part = base_part.substr(0, be+1);
      auto hexStr = [](int64_t v) { std::ostringstream o; o << std::hex << v; return o.str(); };
      result.push_back("s_load_dwordx2 s[" + std::to_string(lo) + ":" +
                        std::to_string(lo+1) + "]" + base_part + ", 0x" + hexStr(offset_val));
      result.push_back("s_load_dword s" + std::to_string(lo+2) + base_part +
                        ", 0x" + hexStr(offset_val + 8));
    }
  }
  if (result.empty()) {
    std::string new_line = line;
    size_t mpos = new_line.find("s_load_b96");
    new_line.replace(mpos, 10, "s_load_dwordx3");
    int lo2 = 0, hi2 = 0;
    if (parseSGPRRange(new_line, lo2, hi2)) {
      size_t spos = new_line.find("s[");
      size_t cpos = new_line.find(']', spos);
      std::string wider = "s[" + std::to_string(lo2) + ":" + std::to_string(lo2 + 2) + "]";
      new_line = new_line.substr(0, spos) + wider + new_line.substr(cpos + 1);
    }
    result.push_back(new_line);
  }
  return result;
}

// ── Handler: Bitop Instructions ──────────────────────────────────────────────

static TranslationResult HandleBitopInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int, int, bool) {
  if (mnemonic.find("v_bitop") != 0) return std::nullopt;
  std::string ops = line.substr(line.find(mnemonic) + mnemonic.size());
  size_t bitop_pos = ops.find("bitop3:");
  if (bitop_pos != std::string::npos) {
    ops = ops.substr(0, bitop_pos);
  }
  auto operands = ParseOperandList(line, mnemonic);
  if (bitop_pos != std::string::npos && operands.size() >= 3) {
    std::vector<std::string> clean;
    for (auto& op : operands)
      if (op.find("bitop") == std::string::npos) clean.push_back(op);
    if (clean.size() >= 3) {
      int truth_table_val = 0;
      std::string hex_str2 = ops.substr(ops.find("bitop3:") != std::string::npos ? ops.find("bitop3:") + 7 : 0);
      std::string all_ops = line.substr(line.find(mnemonic) + mnemonic.size());
      size_t bp = all_ops.find("bitop3:");
      if (bp != std::string::npos) {
        {
          std::string tt_str = all_ops.substr(bp + 7);
          const char* tb = tt_str.data();
          const char* te = tb + tt_str.size();
          int tbase = 10;
          if (tt_str.size() > 2 && tt_str[0] == '0' &&
              (tt_str[1] == 'x' || tt_str[1] == 'X')) {
            tbase = 16; tb += 2;
          }
          std::from_chars(tb, te, truth_table_val, tbase);
        }
      }
      if (truth_table_val == 0xCA)
        return std::vector<std::string>{"v_bfi_b32 " + clean[0] + ", " + clean[1] + ", " + clean[2] + ", " + clean[0]};
      return std::vector<std::string>{"v_and_b32 " + clean[0] + ", " + clean[1] + ", " + clean[2]};
    }
  }
  if (operands.size() >= 3)
    return std::vector<std::string>{"v_and_b32_e32 " + operands[0] + ", " + operands[1] + ", " + operands[2]};
  return std::vector<std::string>{"s_nop 0 ; UNSUPPORTED: " + line};
}

// ── Handler: SALU Float / Scalar Emulation ───────────────────────────────────

static TranslationResult HandleSALUFloat(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int scale_temp_vgpr, int, bool) {
  const std::string vtemp = "v" + std::to_string(scale_temp_vgpr);
  // s_add_nc_u64 / s_sub_nc_u64
  if (mnemonic == "s_add_nc_u64" || mnemonic == "s_sub_nc_u64") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 3) {
      auto parseSpair = [](const std::string& s) -> std::pair<int,int> {
        auto bracket = s.find('[');
        if (bracket == std::string::npos) return {-1,-1};
        int lo=0, hi=0; size_t p = bracket+1;
        while (p<s.size()&&s[p]>='0'&&s[p]<='9') lo=lo*10+(s[p++]-'0');
        if (p<s.size()&&s[p]==':') p++;
        while (p<s.size()&&s[p]>='0'&&s[p]<='9') hi=hi*10+(s[p++]-'0');
        return {lo, hi};
      };
      auto [d0,d1] = parseSpair(operands[0]);
      auto [a0,a1] = parseSpair(operands[1]);
      auto [s0,s1] = parseSpair(operands[2]);
      std::string src_lo = (s0>=0) ? "s"+std::to_string(s0) : operands[2];
      std::string src_hi = (s0>=0) ? "s"+std::to_string(s1) : "0";
      bool is_sub = mnemonic.find("sub") != std::string::npos;
      std::string op = is_sub ? "s_sub_u32" : "s_add_u32";
      std::string opc = is_sub ? "s_subb_u32" : "s_addc_u32";
      return std::vector<std::string>{
        op + " s" + std::to_string(d0) + ", s" + std::to_string(a0) + ", " + src_lo,
        opc + " s" + std::to_string(d1) + ", s" + std::to_string(a1) + ", " + src_hi
      };
    }
    return std::vector<std::string>{"s_nop 0 ; UNSUPPORTED: " + line};
  }

  // s_mul_u64: expand to 32-bit partial products via VALU scratch VGPRs.
  // d[lo:hi] = a[lo:hi] * b[lo:hi] (low 64 bits of 128-bit product)
  if (mnemonic == "s_mul_u64") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 3) {
      auto parseSpair = [](const std::string& s) -> std::pair<int,int> {
        auto bracket = s.find('[');
        if (bracket == std::string::npos) return {-1,-1};
        int lo=0, hi=0; size_t p = bracket+1;
        while (p<s.size()&&s[p]>='0'&&s[p]<='9') lo=lo*10+(s[p++]-'0');
        if (p<s.size()&&s[p]==':') ++p;
        while (p<s.size()&&s[p]>='0'&&s[p]<='9') hi=hi*10+(s[p++]-'0');
        return {lo,hi};
      };
      auto [dl,dh] = parseSpair(operands[0]);
      auto [al,ah] = parseSpair(operands[1]);
      auto [bl,bh] = parseSpair(operands[2]);
      if (dl >= 0 && al >= 0 && bl >= 0) {
        std::string sd_lo = "s" + std::to_string(dl);
        std::string sd_hi = "s" + std::to_string(dh);
        std::string sa_lo = "s" + std::to_string(al);
        std::string sa_hi = "s" + std::to_string(ah);
        std::string sb_lo = "s" + std::to_string(bl);
        std::string sb_hi = "s" + std::to_string(bh);
        std::vector<std::string> result;
        result.push_back("v_mov_b32_e32 " + vtemp + ", " + sa_lo);
        result.push_back("v_mul_lo_u32 v252, " + vtemp + ", " + sb_lo);
        result.push_back("v_mul_hi_u32 v253, " + vtemp + ", " + sb_lo);
        result.push_back("v_mul_lo_u32 " + vtemp + ", " + sa_hi + ", " + sb_lo);
        result.push_back("v_add_u32_e32 v253, v253, " + vtemp);
        result.push_back("v_mov_b32_e32 " + vtemp + ", " + sa_lo);
        result.push_back("v_mul_lo_u32 " + vtemp + ", " + vtemp + ", " + sb_hi);
        result.push_back("v_add_u32_e32 v253, v253, " + vtemp);
        result.push_back("v_readfirstlane_b32 " + sd_lo + ", v252");
        result.push_back("v_readfirstlane_b32 " + sd_hi + ", v253");
        return result;
      }
    }
    return std::vector<std::string>{"s_nop 0 ; UNSUPPORTED: " + line};
  }

  // s_lshlN_add_u32
  {
    int shift_amt = -1;
    if (mnemonic == "s_lshl1_add_u32") shift_amt = 1;
    else if (mnemonic == "s_lshl2_add_u32") shift_amt = 2;
    else if (mnemonic == "s_lshl3_add_u32") shift_amt = 3;
    else if (mnemonic == "s_lshl4_add_u32") shift_amt = 4;
    if (shift_amt >= 0) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 3) {
        std::vector<std::string> result;
        result.push_back("s_lshl_b32 " + operands[0] + ", " + operands[1] + ", " + std::to_string(shift_amt));
        if (operands[2] != "0")
          result.push_back("s_add_u32 " + operands[0] + ", " + operands[0] + ", " + operands[2]);
        return result;
      }
    }
  }

  // SALU float → VALU emulation
  {
    static const std::unordered_map<std::string, std::string> kSaluFloatMap = {
        {"s_add_f32", "v_add_f32_e32"}, {"s_sub_f32", "v_sub_f32_e32"},
        {"s_mul_f32", "v_mul_f32_e32"}, {"s_min_f32", "v_min_f32_e32"},
        {"s_max_f32", "v_max_f32_e32"}, {"s_fmac_f32", "v_fmac_f32_e32"},
        {"s_add_f16", "v_add_f16_e32"}, {"s_sub_f16", "v_sub_f16_e32"},
        {"s_mul_f16", "v_mul_f16_e32"}, {"s_min_f16", "v_min_f16_e32"},
        {"s_max_f16", "v_max_f16_e32"},
    };
    auto salu_it = kSaluFloatMap.find(mnemonic);
    if (salu_it != kSaluFloatMap.end()) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 3) {
        std::vector<std::string> result;
        if (mnemonic == "s_fmac_f32") {
          result.push_back("v_mov_b32_e32 " + vtemp + ", " + operands[1]);
          result.push_back("v_mul_f32_e32 " + vtemp + ", " + operands[2] + ", " + vtemp);
          result.push_back("v_add_f32_e32 " + vtemp + ", " + operands[0] + ", " + vtemp);
          result.push_back("v_readfirstlane_b32 " + operands[0] + ", " + vtemp);
        } else {
          result.push_back("v_mov_b32_e32 " + vtemp + ", " + operands[1]);
          result.push_back(salu_it->second + " " + vtemp + ", " + operands[2] + ", " + vtemp);
          result.push_back("v_readfirstlane_b32 " + operands[0] + ", " + vtemp);
        }
        return result;
      }
    }
  }

  // s_cvt_*
  if (mnemonic == "s_cvt_f32_f16" || mnemonic == "s_cvt_f16_f32" ||
      mnemonic == "s_cvt_pk_rtz_f16_f32" ||
      mnemonic == "s_cvt_f32_u32" || mnemonic == "s_cvt_f32_i32" ||
      mnemonic == "s_cvt_u32_f32" || mnemonic == "s_cvt_i32_f32") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 2) {
      std::string valu_mnem;
      if (mnemonic == "s_cvt_f32_f16") valu_mnem = "v_cvt_f32_f16_e32";
      else if (mnemonic == "s_cvt_f16_f32") valu_mnem = "v_cvt_f16_f32_e32";
      else if (mnemonic == "s_cvt_f32_u32") valu_mnem = "v_cvt_f32_u32_e32";
      else if (mnemonic == "s_cvt_f32_i32") valu_mnem = "v_cvt_f32_i32_e32";
      else if (mnemonic == "s_cvt_u32_f32") valu_mnem = "v_cvt_u32_f32_e32";
      else if (mnemonic == "s_cvt_i32_f32") valu_mnem = "v_cvt_i32_f32_e32";
      else valu_mnem = "v_cvt_pkrtz_f16_f32";
      return std::vector<std::string>{
        valu_mnem + " " + vtemp + ", " + operands[1],
        "v_readfirstlane_b32 " + operands[0] + ", " + vtemp
      };
    }
  }

  // Unary SALU float → VALU emulation (s_trunc_f32, s_ceil_f32, s_floor_f32, etc.)
  {
    static const std::unordered_map<std::string, std::string> kSaluUnaryFloatMap = {
        {"s_trunc_f32", "v_trunc_f32_e32"},
        {"s_ceil_f32", "v_ceil_f32_e32"},
        {"s_floor_f32", "v_floor_f32_e32"},
        {"s_rndne_f32", "v_rndne_f32_e32"},
        {"s_cvt_f32_i32", "v_cvt_f32_i32_e32"},
        {"s_cvt_f32_u32", "v_cvt_f32_u32_e32"},
        {"s_cvt_i32_f32", "v_cvt_i32_f32_e32"},
        {"s_cvt_u32_f32", "v_cvt_u32_f32_e32"},
    };
    auto su_it = kSaluUnaryFloatMap.find(mnemonic);
    if (su_it != kSaluUnaryFloatMap.end()) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 2)
        return std::vector<std::string>{
          su_it->second + " " + vtemp + ", " + operands[1],
          "v_readfirstlane_b32 " + operands[0] + ", " + vtemp
        };
    }
  }

  // v_s_sqrt_f32
  if (mnemonic == "v_s_sqrt_f32") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 2)
      return std::vector<std::string>{
        "v_sqrt_f32_e32 " + vtemp + ", " + operands[1],
        "v_readfirstlane_b32 " + operands[0] + ", " + vtemp
      };
  }

  // v_s_rcp_f32, v_s_rsq_f32, v_s_log_f32, v_s_exp_f32 — GFX12 scalar-in-vector
  {
    static const std::unordered_map<std::string, std::string> kVSMap = {
        {"v_s_rcp_f32", "v_rcp_f32_e32"},
        {"v_s_rsq_f32", "v_rsq_f32_e32"},
        {"v_s_log_f32", "v_log_f32_e32"},
        {"v_s_exp_f32", "v_exp_f32_e32"},
    };
    auto vs_it = kVSMap.find(mnemonic);
    if (vs_it != kVSMap.end()) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 2)
        return std::vector<std::string>{
          vs_it->second + " " + vtemp + ", " + operands[1],
          "v_readfirstlane_b32 " + operands[0] + ", " + vtemp
        };
    }
  }

  // s_cmp_*_f32
  {
    static const std::unordered_map<std::string, std::string> kScmpFloatMap = {
      {"s_cmp_gt_f32", "v_cmp_gt_f32_e32"}, {"s_cmp_ge_f32", "v_cmp_ge_f32_e32"},
      {"s_cmp_lt_f32", "v_cmp_lt_f32_e32"}, {"s_cmp_le_f32", "v_cmp_le_f32_e32"},
      {"s_cmp_eq_f32", "v_cmp_eq_f32_e32"}, {"s_cmp_lg_f32", "v_cmp_lg_f32_e32"},
    };
    auto cmp_it = kScmpFloatMap.find(mnemonic);
    if (cmp_it != kScmpFloatMap.end()) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 2)
        return std::vector<std::string>{
          "v_mov_b32_e32 " + vtemp + ", " + operands[1],
          cmp_it->second + " " + operands[0] + ", " + vtemp,
          "s_cmp_lg_u32 vcc_lo, 0"
        };
    }
  }

  return std::nullopt;
}

// ── Handler: VOPD (dual-issue) ───────────────────────────────────────────────

static TranslationResult HandleVOPDInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string& source_cpu, const std::string& target_cpu,
    int scale_temp_vgpr, int cmpx_temp_sgpr, bool compact_mode) {
  if (mnemonic.find("v_dual_") != 0) return std::nullopt;
  size_t sep = line.find("::");
  if (sep == std::string::npos) return std::nullopt;
  std::string first_half = line.substr(0, sep);
  size_t fs = first_half.find_first_not_of(" \t");
  if (fs != std::string::npos) first_half = first_half.substr(fs);
  size_t fe = first_half.find_last_not_of(" \t");
  if (fe != std::string::npos) first_half = first_half.substr(0, fe + 1);
  if (first_half.find("v_dual_") == 0) first_half = "v_" + first_half.substr(7);
  std::string second_half = line.substr(sep + 2);
  size_t ss = second_half.find_first_not_of(" \t");
  if (ss != std::string::npos) second_half = second_half.substr(ss);
  size_t se = second_half.find_last_not_of(" \t");
  if (se != std::string::npos) second_half = second_half.substr(0, se + 1);
  if (second_half.find("v_dual_") == 0) second_half = "v_" + second_half.substr(7);
  auto r1 = TranslateInstruction(first_half, source_cpu, target_cpu, scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
  auto r2 = TranslateInstruction(second_half, source_cpu, target_cpu, scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
  std::vector<std::string> result;
  result.insert(result.end(), r1.begin(), r1.end());
  result.insert(result.end(), r2.begin(), r2.end());
  return result;
}

// ── Handler: WMMA Instructions ───────────────────────────────────────────────

static TranslationResult HandleWMMAInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string& target_cpu,
    int scale_temp_vgpr, int cmpx_temp_sgpr, bool);

// ── Handler: Constant Bus Fix ────────────────────────────────────────────────

static TranslationResult HandleConstantBusFix(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int, int, bool);

// ── Handler: Memory Instructions ─────────────────────────────────────────────

static TranslationResult HandleMemoryInstruction(
    std::string& line, std::string& mnemonic,
    const std::string&, const std::string&, int scale_temp_vgpr, int, bool);

// ── Handler: EXEC Operations ─────────────────────────────────────────────────

static TranslationResult HandleExecOperation(
    std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&,
    int scale_temp_vgpr, int cmpx_temp_sgpr, bool compact_mode);


// ── Handler: v_add_nc_u64 / v_mad_u32 ────────────────────────────────────────

static TranslationResult Handle64BitVALU(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int scale_temp_vgpr, int, bool) {
  const std::string vtemp = "v" + std::to_string(scale_temp_vgpr);
  if (mnemonic == "v_add_nc_u64" || mnemonic == "v_add_nc_u64_e32" ||
      mnemonic == "v_add_nc_u64_e64" ||
      mnemonic == "v_add_u64" || mnemonic == "v_add_u64_e32" ||
      mnemonic == "v_add_u64_e64") {
    std::string ops = line.substr(line.find(mnemonic) + mnemonic.size());
    struct RegOrImm { char prefix; int lo; int hi; std::string imm; };
    auto parseOperand = [](const std::string& s, size_t& pos) -> RegOrImm {
      while (pos < s.size() && (s[pos]==' '||s[pos]==','||s[pos]=='\t')) ++pos;
      if (pos >= s.size()) return {'?', -1, -1, ""};
      char prefix = s[pos];
      if (prefix == 'v' || prefix == 's') {
        ++pos;
        if (pos < s.size() && s[pos] == '[') {
          ++pos; int lo=0, hi=0;
          while (pos<s.size()&&s[pos]>='0'&&s[pos]<='9') lo=lo*10+(s[pos++]-'0');
          if (pos<s.size()&&s[pos]==':') ++pos;
          while (pos<s.size()&&s[pos]>='0'&&s[pos]<='9') hi=hi*10+(s[pos++]-'0');
          if (pos<s.size()&&s[pos]==']') ++pos;
          return {prefix, lo, hi, ""};
        }
        return {'?', -1, -1, ""};
      }
      size_t st = pos;
      if (s[pos]=='-') ++pos;
      while (pos<s.size()&&(std::isalnum(s[pos])||s[pos]=='x')) ++pos;
      return {'#', 0, 0, s.substr(st, pos-st)};
    };
    size_t pos = 0;
    auto d = parseOperand(ops, pos);
    auto a = parseOperand(ops, pos);
    auto b = parseOperand(ops, pos);
    if (d.lo >= 0 && (a.lo >= 0 || a.prefix == '#') && (b.lo >= 0 || b.prefix == '#')) {
      auto fmtPair = [&](char p, int lo, int hi) -> std::string {
        return std::string(1, p) + "[" + std::to_string(lo) + ":" + std::to_string(hi) + "]";
      };
      std::vector<std::string> result;
      std::string src0_pair;
      if (a.prefix == 'v' || a.prefix == 's')
        src0_pair = fmtPair(a.prefix, a.lo, a.hi);
      else {
        result.push_back("v_mov_b32_e32 v252, " + a.imm);
        result.push_back("v_mov_b32_e32 v253, 0");
        src0_pair = "v[252:253]";
      }
      std::string src1 = (b.prefix == '#') ? b.imm : fmtPair(b.prefix, b.lo, b.hi);
      result.push_back("v_lshl_add_u64 " + fmtPair(d.prefix, d.lo, d.hi) + ", " + src0_pair + ", 0, " + src1);
      return result;
    }
    return std::vector<std::string>{"s_nop 0 ; UNSUPPORTED: " + line};
  }

  // v_mul_u64: expand to 32-bit partial products
  if (mnemonic == "v_mul_u64_e32" || mnemonic == "v_mul_u64") {
    std::string ops = line.substr(line.find(mnemonic) + mnemonic.size());
    auto parseOperand = [](const std::string& s, size_t& pos) -> std::pair<char, std::string> {
      while (pos < s.size() && (s[pos]==' '||s[pos]==','||s[pos]=='\t')) ++pos;
      if (pos >= s.size()) return {'?', ""};
      size_t start = pos;
      if (s[pos] == 'v' || s[pos] == 's') {
        char prefix = s[pos]; ++pos;
        if (pos < s.size() && s[pos] == '[') {
          while (pos < s.size() && s[pos] != ']') ++pos;
          if (pos < s.size()) ++pos;
        } else {
          while (pos < s.size() && std::isdigit(s[pos])) ++pos;
        }
        return {prefix, s.substr(start, pos - start)};
      }
      while (pos < s.size() && !std::isspace(s[pos]) && s[pos] != ',') ++pos;
      return {'#', s.substr(start, pos - start)};
    };
    size_t pos = 0;
    auto [dc, dst] = parseOperand(ops, pos);
    auto [ac, src0] = parseOperand(ops, pos);
    auto [bc, src1] = parseOperand(ops, pos);
    if (dc == 'v' && dst.find('[') != std::string::npos) {
      auto parsePair = [](const std::string& s) -> std::pair<int,int> {
        auto br = s.find('[');
        if (br == std::string::npos) return {-1,-1};
        int lo=0, hi=0; size_t p = br+1;
        while (p<s.size()&&s[p]>='0'&&s[p]<='9') lo=lo*10+(s[p++]-'0');
        if (p<s.size()&&s[p]==':') ++p;
        while (p<s.size()&&s[p]>='0'&&s[p]<='9') hi=hi*10+(s[p++]-'0');
        return {lo,hi};
      };
      auto [dl, dh] = parsePair(dst);
      std::string d_lo = "v" + std::to_string(dl);
      std::string d_hi = "v" + std::to_string(dh);
      std::vector<std::string> result;
      result.push_back("v_mul_lo_u32 " + d_lo + ", " + src0 + ", " + src1);
      result.push_back("v_mul_hi_u32 " + d_hi + ", " + src0 + ", " + src1);
      return result;
    }
  }

  if (mnemonic == "v_mad_u32") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 4) {
      std::vector<std::string> result;
      std::string vdst = operands[0], src0 = operands[1], src1 = operands[2], src2 = operands[3];
      bool src0_sgpr = !src0.empty() && src0[0] == 's';
      bool src1_sgpr = !src1.empty() && src1[0] == 's';
      if (vdst != src2) {
        if (src0_sgpr && src1_sgpr) {
          result.push_back("v_mov_b32_e32 " + vtemp + ", " + src0);
          result.push_back("v_mul_lo_u32 " + vdst + ", " + vtemp + ", " + src1);
        } else {
          result.push_back("v_mul_lo_u32 " + vdst + ", " + src0 + ", " + src1);
        }
        result.push_back("v_add_u32_e32 " + vdst + ", " + vdst + ", " + src2);
      } else {
        result.push_back("v_mov_b32_e32 " + vtemp + ", " + src0);
        result.push_back("v_mul_lo_u32 " + vtemp + ", " + vtemp + ", " + src1);
        result.push_back("v_add_u32_e32 " + vdst + ", " + vtemp + ", " + src2);
      }
      return result;
    }
  }

  return std::nullopt;
}

// ── HandleConstantBusFix implementation ──────────────────────────────────────

static TranslationResult HandleConstantBusFix(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&, int scale_temp_vgpr, int cmpx_temp_sgpr, bool) {
  const std::string vtemp = "v" + std::to_string(scale_temp_vgpr);
  const std::string stemp = "s" + std::to_string(cmpx_temp_sgpr);
  // v_cndmask_b32_e64
  if (mnemonic == "v_cndmask_b32_e64") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 4) {
      std::vector<std::string> result;
      for (auto& op : operands) { if (op == "vcc_lo") op = "vcc"; }
      auto& mask = operands[3];
      // GFX9 v_cndmask_b32 requires VCC or SGPR pair as mask, not VGPR.
      // If mask is a VGPR, convert to VCC first.
      if (!mask.empty() && mask[0] == 'v' && mask.find("vcc") == std::string::npos) {
        result.push_back("v_cmp_ne_u32_e32 vcc, 0, " + mask);
        mask = "vcc";
      }
      // Expand single SGPR to even-aligned pair for 64-bit mask
      if (!mask.empty() && mask[0] == 's' && mask.find('[') == std::string::npos &&
          mask.find("vcc") == std::string::npos && mask.find("exec") == std::string::npos &&
          mask.size() > 1 && std::isdigit((unsigned char)mask[1])) {
        int n = 0;
        std::from_chars(mask.data() + 1, mask.data() + mask.size(), n);
        int even = n & ~1;
        mask = "s[" + std::to_string(even) + ":" + std::to_string(even + 1) + "]";
      }
      // Check for constant bus conflict: if both a source operand and the
      // mask are different SGPRs/VCC, move the SGPR source to a VGPR.
      auto isSGPRorVCC = [](const std::string& op) -> bool {
        if (op == "vcc" || op == "vcc_lo") return true;
        return !op.empty() && op[0] == 's' && op.size() > 1 &&
               (std::isdigit((unsigned char)op[1]) || op[1] == '[');
      };
      auto sgprBase = [](const std::string& op) -> std::string {
        if (op == "vcc" || op == "vcc_lo") return "vcc";
        if (op.find('[') != std::string::npos) return op.substr(0, op.find(']') + 1);
        size_t e = 1;
        while (e < op.size() && std::isdigit((unsigned char)op[e])) ++e;
        return op.substr(0, e);
      };
      bool mask_is_sgpr = isSGPRorVCC(mask);
      if (mask_is_sgpr) {
        std::string mask_base = sgprBase(mask);
        // Move any SGPR source that differs from the mask base to a VGPR
        for (int si = 1; si <= 2 && si < (int)operands.size(); ++si) {
          if (isSGPRorVCC(operands[si]) && sgprBase(operands[si]) != mask_base) {
            result.push_back("v_mov_b32_e32 " + vtemp + ", " + operands[si]);
            operands[si] = vtemp;
          }
        }
      }
      std::string fixed = mnemonic + " " + operands[0];
      for (size_t i = 1; i < operands.size(); ++i) fixed += ", " + operands[i];
      result.push_back(fixed);
      return result;
    }
  }
  // v_cndmask_b32_e32 SGPR src0
  if (mnemonic == "v_cndmask_b32_e32") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 3) {
      std::string& src0 = operands[1];
      bool src0_sgpr = !src0.empty() && src0[0] == 's';
      bool src0_lit = src0.size() > 2 && src0[0] == '0' && (src0[1] == 'x' || src0[1] == 'X');
      if (src0_sgpr || src0_lit) {
        std::vector<std::string> result;
        result.push_back("v_mov_b32_e32 " + vtemp + ", " + src0);
        src0 = vtemp;
        std::string fixed = mnemonic + " " + operands[0];
        for (size_t i = 1; i < operands.size(); ++i) fixed += ", " + operands[i];
        result.push_back(fixed);
        return result;
      }
    }
  }
  // v_cndmask_b32 (no suffix) with explicit mask
  if (mnemonic == "v_cndmask_b32") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 4) {
      for (auto& op : operands) { if (op == "vcc_lo") op = "vcc"; }
      auto& mask = operands[3];
      if (!mask.empty() && mask[0] == 's' && mask.find('[') == std::string::npos &&
          mask.find("vcc") == std::string::npos && mask.find("exec") == std::string::npos &&
          mask.size() > 1 && std::isdigit((unsigned char)mask[1])) {
        int n = 0;
        std::from_chars(mask.data() + 1, mask.data() + mask.size(), n);
        int even = n & ~1;
        mask = "s[" + std::to_string(even) + ":" + std::to_string(even + 1) + "]";
      }
      std::string fixed = "v_cndmask_b32_e64 " + operands[0];
      for (size_t i = 1; i < operands.size(); ++i) fixed += ", " + operands[i];
      return std::vector<std::string>{fixed};
    }
  }
  // DPP8
  if (line.find("dpp8:") != std::string::npos) {
    size_t dpp8_pos = line.find("dpp8:[");
    if (dpp8_pos != std::string::npos) {
      std::string base_part = line.substr(0, dpp8_pos);
      size_t be = base_part.find_last_not_of(" \t");
      if (be != std::string::npos) base_part = base_part.substr(0, be + 1);
      if (line.find("dpp8:[0,1,2,3,4,5,6,7]") != std::string::npos) {
        std::string no_dpp = base_part;
        size_t dpp_suffix = no_dpp.find("_dpp");
        if (dpp_suffix != std::string::npos) no_dpp.replace(dpp_suffix, 4, "_e32");
        return std::vector<std::string>{no_dpp};
      }
      return std::vector<std::string>{base_part + " row_shr:0 row_mask:0xf bank_mask:0xf"};
    }
  }
  // VOP3 with 32-bit literal
  {
    bool is_vop3_candidate =
        mnemonic == "v_fma_f32" || mnemonic == "v_fma_f16" ||
        mnemonic == "v_fma_f64" || mnemonic == "v_ldexp_f32" ||
        mnemonic == "v_div_fmas_f32" || mnemonic == "v_div_fixup_f32" ||
        mnemonic == "v_med3_f32" || mnemonic == "v_med3_i32" ||
        mnemonic == "v_bfi_b32" || mnemonic == "v_alignbit_b32" ||
        mnemonic == "v_add3_u32" || mnemonic == "v_and_or_b32" ||
        mnemonic == "v_or3_b32" || mnemonic == "v_xad_u32" ||
        mnemonic == "v_add_lshl_u32" || mnemonic == "v_lshl_add_u32" ||
        mnemonic == "v_lshl_or_b32" ||
        mnemonic == "v_mul_lo_u32" || mnemonic == "v_mul_hi_u32" ||
        mnemonic == "v_mul_hi_i32";
    if (is_vop3_candidate) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 3) {
        auto isSGPR = [](const std::string& op) -> bool {
          if (op.empty()) return false;
          std::string s = op;
          if (s[0] == '-') s = s.substr(1);
          return !s.empty() && s[0] == 's' && s.size() > 1 &&
                 (std::isdigit((unsigned char)s[1]) || s[1] == '[');
        };
        auto isLiteral = [](const std::string& op) -> bool {
          std::string s = op;
          if (!s.empty() && s[0] == '-') s = s.substr(1);
          return s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
        };

        // Fix 32-bit hex literals
        for (size_t i = 1; i < operands.size(); ++i) {
          if (isLiteral(operands[i])) {
            std::string op = operands[i];
            bool neg = !op.empty() && op[0] == '-';
            if (neg) op = op.substr(1);
            std::vector<std::string> result;
            result.push_back("v_mov_b32_e32 " + vtemp + ", " + op);
            operands[i] = (neg ? "-" : "") + vtemp;
            std::string fixed = mnemonic + " " + operands[0];
            for (size_t j = 1; j < operands.size(); ++j) fixed += ", " + operands[j];
            result.push_back(fixed);
            return result;
          }
        }

        // Fix constant bus violation: two different SGPRs as sources
        int sgpr_count = 0;
        size_t second_sgpr_idx = 0;
        std::string first_sgpr;
        for (size_t i = 1; i < operands.size(); ++i) {
          if (isSGPR(operands[i])) {
            std::string base = operands[i];
            if (base[0] == '-') base = base.substr(1);
            if (sgpr_count == 0) { first_sgpr = base; ++sgpr_count; }
            else if (base != first_sgpr) { second_sgpr_idx = i; ++sgpr_count; break; }
          }
        }
        if (sgpr_count >= 2 && second_sgpr_idx > 0) {
          std::vector<std::string> result;
          std::string op = operands[second_sgpr_idx];
          bool neg = !op.empty() && op[0] == '-';
          if (neg) op = op.substr(1);
          result.push_back("v_mov_b32_e32 " + vtemp + ", " + op);
          operands[second_sgpr_idx] = (neg ? "-" : "") + vtemp;
          std::string fixed = mnemonic + " " + operands[0];
          for (size_t j = 1; j < operands.size(); ++j) fixed += ", " + operands[j];
          result.push_back(fixed);
          return result;
        }
      }
    }
  }
  // v_perm_b32 with literal constant
  if (mnemonic == "v_perm_b32") {
    std::string ops = line.substr(line.find(mnemonic) + mnemonic.size());
    if (ops.find("0x") != std::string::npos) {
      auto operands = ParseOperandList(line, mnemonic);
      if (operands.size() >= 4) {
        return std::vector<std::string>{
          "s_mov_b32 " + stemp + ", " + operands[3],
          "v_perm_b32 " + operands[0] + ", " + operands[1] + ", " + operands[2] + ", " + stemp
        };
      }
    }
  }
  // v_fmamk_f32 / v_fmaak_f32
  if (mnemonic == "v_fmamk_f32" || mnemonic == "v_fmaak_f32") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 4) {
      std::vector<std::string> result;
      const std::string& literal = (mnemonic == "v_fmamk_f32") ? operands[2] : operands[3];
      result.push_back("v_mov_b32_e32 " + vtemp + ", " + literal);
      if (mnemonic == "v_fmamk_f32")
        result.push_back("v_fma_f32 " + operands[0] + ", " + operands[1] + ", " + vtemp + ", " + operands[3]);
      else
        result.push_back("v_fma_f32 " + operands[0] + ", " + operands[1] + ", " + operands[2] + ", " + vtemp);
      return result;
    }
  }
  return std::nullopt;
}

// ── HandleMemoryInstruction implementation ───────────────────────────────────

static TranslationResult HandleMemoryInstruction(
    std::string& line, std::string& mnemonic,
    const std::string&, const std::string&, int scale_temp_vgpr, int, bool) {
  // scale_offset emulation
  if (line.find("scale_offset") != std::string::npos) {
    int shift = 0;
    if (mnemonic.find("_b32") != std::string::npos || mnemonic.find("_dword") != std::string::npos) shift = 2;
    else if (mnemonic.find("_b64") != std::string::npos || mnemonic.find("_dwordx2") != std::string::npos) shift = 3;
    else if (mnemonic.find("_b128") != std::string::npos || mnemonic.find("_dwordx4") != std::string::npos) shift = 4;
    else if (mnemonic.find("_b16") != std::string::npos) shift = 1;
    if (shift > 0) {
      size_t mnem_end = line.find(mnemonic) + mnemonic.size();
      std::string ops = line.substr(mnem_end);
      bool is_store = mnemonic.find("store") != std::string::npos;
      std::string vaddr;
      if (is_store) {
        size_t s = ops.find_first_not_of(" \t");
        size_t e = ops.find_first_of(" \t,", s);
        if (s != std::string::npos) vaddr = ops.substr(s, e != std::string::npos ? e - s : std::string::npos);
      } else {
        size_t comma1 = ops.find(',');
        if (comma1 != std::string::npos) {
          size_t s = ops.find_first_not_of(" \t,", comma1 + 1);
          size_t e = ops.find_first_of(" \t,", s);
          if (s != std::string::npos) vaddr = ops.substr(s, e != std::string::npos ? e - s : std::string::npos);
        }
      }
      if (!vaddr.empty()) {
        std::vector<std::string> result;
        const std::string kScaleTemp = "v" + std::to_string(scale_temp_vgpr);
        result.push_back("v_lshlrev_b32_e32 " + kScaleTemp + ", " + std::to_string(shift) + ", " + vaddr);
        std::string modified = line;
        size_t vaddr_pos = modified.find(vaddr, mnem_end);
        if (vaddr_pos != std::string::npos) modified.replace(vaddr_pos, vaddr.size(), kScaleTemp);
        size_t so_pos = modified.find("scale_offset");
        if (so_pos != std::string::npos) {
          if (so_pos > 0 && modified[so_pos-1] == ' ') --so_pos;
          modified.erase(so_pos);
        }
        line = modified;
        mnemonic = TranspileExtractMnemonic(line);
      }
    }
  }
  return std::nullopt;
}

// ── HandleWMMAInstruction implementation ─────────────────────────────────────

static TranslationResult HandleWMMAInstruction(
    const std::string& line, const std::string& mnemonic,
    const std::string&, const std::string& target_cpu,
    int scale_temp_vgpr, int cmpx_temp_sgpr, bool) {
  const std::string stemp = "s" + std::to_string(cmpx_temp_sgpr);
  const std::string stemp2 = "s" + std::to_string(cmpx_temp_sgpr + 1);
  struct WmmaMfmaMapping { const char* wmma_mnem; const char* mfma_mnem; int dst_vgprs_w32; int src_vgprs_w32; int dst_vgprs_w64; int src_vgprs_w64; };
  static const WmmaMfmaMapping kWmmaMap[] = {
    {"v_wmma_f32_16x16x32_f16", "v_mfma_f32_16x16x32_f16", 8, 8, 4, 4},
    {"v_wmma_f32_16x16x32_bf16", "v_mfma_f32_16x16x32bf16", 8, 8, 4, 4},
    {"v_wmma_f32_16x16x16_f16", "v_mfma_f32_16x16x16_f16", 8, 4, 4, 2},
    {"v_wmma_f32_16x16x4_f32", "v_mfma_f32_16x16x4_f32", 8, 2, 4, 1},
    {"v_wmma_i32_16x16x64_iu8", "v_mfma_i32_16x16x64_i8", 8, 8, 4, 4},
  };
  const WmmaMfmaMapping* mapping = nullptr;
  for (const auto& m : kWmmaMap)
    if (mnemonic == m.wmma_mnem) { mapping = &m; break; }
  if (!mapping) {
    if (mnemonic.find("v_wmma_") == 0 || mnemonic.find("v_swmmac_") == 0)
      return std::vector<std::string>{"s_nop 0 ; UNSUPPORTED WMMA: " + mnemonic};
    return std::nullopt;
  }
  std::string ops = line.substr(line.find(mnemonic) + mnemonic.size());
  size_t op_start = ops.find_first_not_of(" \t");
  if (op_start != std::string::npos) ops = ops.substr(op_start);
  auto parseVRegRange = [](const std::string& s, size_t& pos) -> std::pair<int, int> {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == ',' || s[pos] == '\t')) ++pos;
    if (pos >= s.size() || s[pos] != 'v') return {-1, -1};
    ++pos;
    if (pos < s.size() && s[pos] == '[') {
      ++pos; int lo = 0, hi = 0;
      while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') lo = lo * 10 + (s[pos++] - '0');
      if (pos < s.size() && s[pos] == ':') ++pos;
      while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') hi = hi * 10 + (s[pos++] - '0');
      if (pos < s.size() && s[pos] == ']') ++pos;
      return {lo, hi};
    }
    return {-1, -1};
  };
  size_t pos = 0;
  auto dst = parseVRegRange(ops, pos);
  auto srcA = parseVRegRange(ops, pos);
  auto srcB = parseVRegRange(ops, pos);
  auto acc = parseVRegRange(ops, pos);
  if (dst.first < 0 || srcA.first < 0 || srcB.first < 0 || acc.first < 0)
    return std::vector<std::string>{"s_nop 0 ; WMMA parse failed: " + line};
  int src_w64 = mapping->src_vgprs_w64;
  int dst_w64 = mapping->dst_vgprs_w64;
  std::string mfma_mnem = mapping->mfma_mnem;
  int wmma_temp_base = (scale_temp_vgpr + 2 >= 248) ? scale_temp_vgpr + 2 : 248;
  int t_lane = wmma_temp_base, t_src = wmma_temp_base + 1,
      t_addr = wmma_temp_base + 2, t_upper = wmma_temp_base + 3,
      t0 = wmma_temp_base + 4, t1 = wmma_temp_base + 5;
  int mfma_srcA = srcA.first, mfma_srcB = srcB.first, mfma_acc = acc.first, mfma_dst = dst.first;
  auto regRange = [](int base, int count) -> std::string {
    if (count == 1) return "v" + std::to_string(base);
    return "v[" + std::to_string(base) + ":" + std::to_string(base + count - 1) + "]";
  };
  std::vector<std::string> result;
  auto emitRedistribute = [&](int base_w32, int out_base, int n_w64) {
    for (int i = 0; i < n_w64; ++i) {
      int lo_reg = base_w32 + i, hi_reg = base_w32 + n_w64 + i;
      result.push_back("ds_bpermute_b32 v" + std::to_string(t0) + ", v" + std::to_string(t_addr) + ", v" + std::to_string(lo_reg));
      result.push_back("ds_bpermute_b32 v" + std::to_string(t1) + ", v" + std::to_string(t_addr) + ", v" + std::to_string(hi_reg));
      result.push_back("s_waitcnt lgkmcnt(0)");
      result.push_back("v_cndmask_b32_e32 v" + std::to_string(out_base + i) + ", v" + std::to_string(t0) + ", v" + std::to_string(t1) + ", vcc");
    }
  };
  result.push_back("; BEGIN WMMA→MFMA: " + mnemonic + " → " + mfma_mnem);
  result.push_back("s_mov_b32 " + stemp + ", exec_lo");
  result.push_back("s_mov_b32 " + stemp2 + ", exec_hi");
  result.push_back("s_mov_b64 exec, -1");
  result.push_back("v_mbcnt_lo_u32_b32 v" + std::to_string(t_lane) + ", -1, 0");
  result.push_back("v_mbcnt_hi_u32_b32 v" + std::to_string(t_lane) + ", -1, v" + std::to_string(t_lane));
  result.push_back("v_lshrrev_b32_e32 v" + std::to_string(t_src) + ", 1, v" + std::to_string(t_lane));
  result.push_back("v_and_b32_e32 v" + std::to_string(t_upper) + ", 1, v" + std::to_string(t_lane));
  result.push_back("v_lshlrev_b32_e32 v" + std::to_string(t_addr) + ", 2, v" + std::to_string(t_src));
  result.push_back("v_cmp_ne_u32 vcc, 0, v" + std::to_string(t_upper));
  emitRedistribute(srcA.first, mfma_srcA, src_w64);
  emitRedistribute(srcB.first, mfma_srcB, src_w64);
  emitRedistribute(acc.first, mfma_acc, dst_w64);
  bool need_decompose = false;
  std::string actual_mfma = mfma_mnem;
  // TODO(gfx950): verify whether gfx950 supports native 16x16x32 MFMA
  if (target_cpu.find("gfx942") != std::string::npos || target_cpu.find("gfx940") != std::string::npos || target_cpu.find("gfx941") != std::string::npos) {
    if (mfma_mnem == "v_mfma_f32_16x16x32_f16" || mfma_mnem == "v_mfma_f32_16x16x32bf16") {
      need_decompose = true;
      actual_mfma = (mfma_mnem.find("bf16") != std::string::npos) ? "v_mfma_f32_16x16x16bf16_1k" : "v_mfma_f32_16x16x16_f16";
    }
  }
  if (need_decompose) {
    int half_src = src_w64 / 2;
    result.push_back(actual_mfma + " " + regRange(mfma_dst, dst_w64) + ", " + regRange(mfma_srcA, half_src) + ", " + regRange(mfma_srcB, half_src) + ", " + regRange(mfma_acc, dst_w64));
    result.push_back(actual_mfma + " " + regRange(mfma_dst, dst_w64) + ", " + regRange(mfma_srcA + half_src, half_src) + ", " + regRange(mfma_srcB + half_src, half_src) + ", " + regRange(mfma_dst, dst_w64));
  } else {
    result.push_back(mfma_mnem + " " + regRange(mfma_dst, dst_w64) + ", " + regRange(mfma_srcA, src_w64) + ", " + regRange(mfma_srcB, src_w64) + ", " + regRange(mfma_acc, dst_w64));
  }
  result.push_back("s_mov_b32 exec_lo, " + stemp);
  result.push_back("s_mov_b32 exec_hi, 0");
  result.push_back("v_mbcnt_lo_u32_b32 v" + std::to_string(t_lane) + ", -1, 0");
  result.push_back("v_lshlrev_b32_e32 v" + std::to_string(t_addr) + ", 3, v" + std::to_string(t_lane));
  result.push_back("v_add_u32_e32 v" + std::to_string(t0) + ", 4, v" + std::to_string(t_addr));
  result.push_back("s_mov_b64 exec, -1");
  for (int i = 0; i < dst_w64; ++i) {
    result.push_back("ds_bpermute_b32 v" + std::to_string(dst.first + i) + ", v" + std::to_string(t_addr) + ", v" + std::to_string(mfma_dst + i));
    result.push_back("s_waitcnt lgkmcnt(0)");
    result.push_back("ds_bpermute_b32 v" + std::to_string(dst.first + dst_w64 + i) + ", v" + std::to_string(t0) + ", v" + std::to_string(mfma_dst + i));
    result.push_back("s_waitcnt lgkmcnt(0)");
  }
  result.push_back("s_waitcnt lgkmcnt(0)");
  result.push_back("s_mov_b32 exec_lo, " + stemp);
  result.push_back("s_mov_b32 exec_hi, " + stemp2);
  result.push_back("; END WMMA→MFMA: " + mfma_mnem);
  return result;
}

// ── HandleExecOperation implementation ───────────────────────────────────────

static TranslationResult HandleExecOperation(
    std::string& line, const std::string& mnemonic,
    const std::string&, const std::string&,
    int scale_temp_vgpr, int cmpx_temp_sgpr, bool compact_mode) {
  (void)scale_temp_vgpr;
  (void)cmpx_temp_sgpr;
  (void)compact_mode;
  // v_div_scale_f32/f64: GFX12 allows arbitrary SGPR as sdst, GFX9 requires VCC
  if (mnemonic == "v_div_scale_f32" || mnemonic == "v_div_scale_f64") {
    auto operands = ParseOperandList(line, mnemonic);
    // Format: vdst, sdst, src0, src1, src2
    if (operands.size() >= 5 && operands[1] != "vcc") {
      operands[1] = "vcc";
      line = mnemonic + " " + operands[0];
      for (size_t i = 1; i < operands.size(); ++i)
        line += ", " + operands[i];
    }
  }
  return std::nullopt;
}


// ── Helper: v_cmp / v_cmpx wave64 expansion ──────────────────────────────────

static bool HandleVCmpExpansion(
    std::string& line, const std::string& mnemonic,
    std::vector<std::string>& result,
    int scale_temp_vgpr, int cmpx_temp_sgpr, bool compact_mode) {
  const std::string vtemp = "v" + std::to_string(scale_temp_vgpr);
  // v_cmp_*_e64 with vcc dest + large literal → VOPC _e32
  if (mnemonic.find("v_cmp_") == 0 && mnemonic.find("_e64") != std::string::npos) {
    size_t op_start = line.find(mnemonic) + mnemonic.size();
    std::string ops_str = line.substr(op_start);
    size_t sp = ops_str.find_first_not_of(" \t");
    if (sp != std::string::npos) ops_str = ops_str.substr(sp);
    size_t first_comma = ops_str.find(',');
    if (first_comma != std::string::npos) {
      std::string first_op = ops_str.substr(0, first_comma);
      size_t fe = first_op.find_last_not_of(" \t");
      if (fe != std::string::npos) first_op = first_op.substr(0, fe + 1);
      if (first_op == "vcc" || first_op == "vcc_lo") {
        auto srcs = ParseOperandList(ops_str.substr(first_comma + 1), "");
        if (srcs.size() >= 2) {
          auto is_ll = [](const std::string& s) -> bool {
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return true;
            long v = 0;
            std::from_chars(s.data(), s.data() + s.size(), v);
            if (!s.empty() && std::isdigit((unsigned char)s[0]) && v > 64) return true;
            if (s.size() > 1 && s[0] == '-' && std::isdigit((unsigned char)s[1]) && v < -16) return true;
            return false;
          };
          std::string base_mnem = mnemonic.substr(0, mnemonic.size() - 4) + "_e32";
          if (is_ll(srcs[1]) && !is_ll(srcs[0])) {
            result.push_back("v_mov_b32_e32 " + vtemp + ", " + srcs[1]);
            result.push_back(base_mnem + " " + srcs[0] + ", " + vtemp);
            return true;
          } else if (is_ll(srcs[0])) {
            result.push_back(base_mnem + " " + srcs[0] + ", " + srcs[1]);
            return true;
          }
        }
      }
    }
  }

  // v_cmpx _e64
  if (mnemonic.find("v_cmpx_") == 0 && mnemonic.find("_e64") != std::string::npos) {
    std::string base_mnem = mnemonic.substr(0, mnemonic.find("_e64"));
    size_t op_start = line.find(mnemonic) + mnemonic.size();
    std::string ops = line.substr(op_start);
    size_t s = ops.find_first_not_of(" \t");
    if (s != std::string::npos) ops = ops.substr(s);
    std::string stemp = "s" + std::to_string(cmpx_temp_sgpr);
    result.push_back("s_mov_b32 " + stemp + ", vcc_lo");
    result.push_back(base_mnem + " " + ops);
    result.push_back("s_mov_b32 vcc_lo, " + stemp);
    return true;
  }

  // v_cmpx _e32
  if (mnemonic.find("v_cmpx_") == 0 && mnemonic.find("_e64") == std::string::npos) {
    std::string stemp = "s" + std::to_string(cmpx_temp_sgpr);
    result.push_back("s_mov_b32 " + stemp + ", vcc_lo");
    result.push_back(line);
    result.push_back("s_mov_b32 exec_hi, 0");
    result.push_back("s_mov_b32 vcc_lo, " + stemp);
    return true;
  }

  // v_cmp _e64 with SGPR dest → expand to SGPR pair
  if (mnemonic.find("v_cmp_") == 0 && mnemonic.find("_e64") != std::string::npos) {
    size_t op_start = line.find(mnemonic) + mnemonic.size();
    std::string ops = line.substr(op_start);
    size_t s_pos = ops.find_first_not_of(" \t");
    if (s_pos != std::string::npos) {
      std::string trimmed = ops.substr(s_pos);
      if (!trimmed.empty() && trimmed[0] == 's' && trimmed.size() > 1 && std::isdigit(trimmed[1])) {
        size_t comma = trimmed.find(',');
        if (comma != std::string::npos) {
          std::string dst_str = trimmed.substr(0, comma);
          size_t de = dst_str.find_last_not_of(" \t");
          dst_str = dst_str.substr(0, de + 1);
          int reg_num = 0;
          std::from_chars(dst_str.data() + 1, dst_str.data() + dst_str.size(), reg_num);
          int even = reg_num & ~1;
          int odd = even + 1;
          std::string pair = "s[" + std::to_string(even) + ":" + std::to_string(odd) + "]";
          std::string rest = trimmed.substr(comma);
          std::string save_reg = "v" + std::to_string(scale_temp_vgpr);
          line = mnemonic + " " + pair + rest;
          if (reg_num == even) {
            if (compact_mode) {
              result.push_back(line);
            } else {
              result.push_back("v_mov_b32_e32 " + save_reg + ", s" + std::to_string(odd));
              result.push_back(line);
              result.push_back("v_readfirstlane_b32 s" + std::to_string(odd) + ", " + save_reg);
            }
          } else {
            result.push_back("v_mov_b32_e32 " + save_reg + ", s" + std::to_string(even));
            result.push_back(line);
            result.push_back("s_mov_b32 s" + std::to_string(reg_num) + ", s" + std::to_string(even));
            result.push_back("v_readfirstlane_b32 s" + std::to_string(even) + ", " + save_reg);
          }
          auto is_ll = [](const std::string& sv) -> bool {
            if (sv.empty()) return false;
            if (sv.size() > 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X')) return true;
            long v = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), v);
            if (std::isdigit((unsigned char)sv[0]) && v > 64) return true;
            if (sv[0] == '-' && sv.size() > 1 && v < -16) return true;
            return false;
          };
          for (size_t ri = 0; ri < result.size(); ri++) {
            if (result[ri].find("v_cmp_") != std::string::npos) {
              size_t lc = result[ri].rfind(',');
              if (lc != std::string::npos) {
                std::string lo = result[ri].substr(lc + 1);
                size_t ls = lo.find_first_not_of(" \t");
                size_t le = lo.find_last_not_of(" \t");
                if (ls != std::string::npos) {
                  std::string lt = lo.substr(ls, le - ls + 1);
                  if (is_ll(lt)) {
                    result.insert(result.begin() + ri, "v_mov_b32_e32 " + vtemp + ", " + lt);
                    result[ri + 1] = result[ri + 1].substr(0, lc + 1) + " " + vtemp;
                  }
                }
              }
              break;
            }
          }
          return true;
        }
      }
    }
    auto is_ll = [](const std::string& sv) -> bool {
      if (sv.empty()) return false;
      if (sv.size() > 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X')) return true;
      long v = 0;
      std::from_chars(sv.data(), sv.data() + sv.size(), v);
      if (std::isdigit((unsigned char)sv[0]) && v > 64) return true;
      if (sv[0] == '-' && sv.size() > 1 && v < -16) return true;
      return false;
    };
    size_t last_comma = line.rfind(',');
    if (last_comma != std::string::npos) {
      std::string last_op = line.substr(last_comma + 1);
      size_t ls = last_op.find_first_not_of(" \t");
      size_t le = last_op.find_last_not_of(" \t");
      if (ls != std::string::npos) {
        std::string lt = last_op.substr(ls, le - ls + 1);
        if (is_ll(lt)) {
          result.push_back("v_mov_b32_e32 " + vtemp + ", " + lt);
          line = line.substr(0, last_comma + 1) + " " + vtemp;
        }
      }
    }
  }

  return false;
}

// ── TranslateInstruction — Opcode-based dispatch with string fallback ────────

std::vector<std::string> TranslateInstruction(const std::string& asm_line,
                                               const std::string& source_cpu,
                                               const std::string& target_cpu,
                                               int scale_temp_vgpr,
                                               int cmpx_temp_sgpr,
                                               bool compact_mode,
                                               unsigned opcode,
                                               const llvm::MCInstrInfo *MCII) {
  std::vector<std::string> result;
  std::string line = asm_line;

  // ── Pre-processing: strip whitespace and comments ──
  size_t start = line.find_first_not_of(" \t");
  if (start == std::string::npos) { result.push_back(line); return result; }
  if (start > 0) line = line.substr(start);

  size_t comment = line.find("//");
  if (comment != std::string::npos) {
    line = line.substr(0, comment);
    size_t end = line.find_last_not_of(" \t");
    if (end != std::string::npos) line = line.substr(0, end + 1);
  }
  if (line.empty()) { result.push_back(""); return result; }

  std::string mnemonic = TranspileExtractMnemonic(line);

  // v_illegal: undecodable instructions from the disassembler → NOP
  if (mnemonic == "v_illegal") {
    result.push_back("s_nop 0");
    return result;
  }

  // GFX12 _nc_ VALU → remove _nc_
  if (mnemonic.find("_nc_") != std::string::npos && mnemonic[0] == 'v') {
    std::string fixed = mnemonic;
    size_t nc_pos = fixed.find("_nc_");
    fixed.replace(nc_pos, 4, "_");
    if (fixed.find("_e32") == std::string::npos && fixed.find("_e64") == std::string::npos)
      fixed += "_e32";
    line = TranspileReplaceMnemonic(line, mnemonic, fixed);
    mnemonic = fixed;
  }

  // v_fmac → v_fma: accumulate form (dst = src0 * src1 + dst) → explicit 3-src
  // Handles both f32 and f16 variants. GFX9 doesn't have v_fmac_f16.
  if (mnemonic == "v_fmac_f32_e32" || mnemonic == "v_fmac_f32" ||
      mnemonic == "v_fmac_f16_e32" || mnemonic == "v_fmac_f16" ||
      mnemonic == "v_fmac_f32_e64" || mnemonic == "v_fmac_f16_e64") {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 3) {
      // v_fmac dst, src0, src1 → v_fma dst, src0, src1, dst
      std::string suffix = mnemonic.find("f16") != std::string::npos ? "f16" : "f32";
      std::string fma_mn = "v_fma_" + suffix;
      line = fma_mn + " " + operands[0] + ", " + operands[1] + ", " +
             operands[2] + ", " + operands[0];
      mnemonic = fma_mn;
    }
  }

  // GFX12 s_and_not1/s_or_not1 → s_andn2/s_orn2
  if (mnemonic.find("_not1_") != std::string::npos && mnemonic[0] == 's') {
    std::string fixed = mnemonic;
    size_t not1_pos = fixed.find("_not1_");
    fixed.replace(not1_pos, 6, "n2_");
    line = TranspileReplaceMnemonic(line, mnemonic, fixed);
    mnemonic = fixed;
  }

  // ── Dispatch: opcode-based (fast) or string-based (fallback) ──

  if (opcode != ~0u && MCII) {
    const llvm::MCInstrDesc &desc = MCII->get(opcode);
    uint64_t tsflags = desc.TSFlags;

    // VALU: bitop instructions
    if (tsflags & llvm::SIInstrFlags::VALU) {
      auto r = HandleBitopInstruction(line, mnemonic, source_cpu, target_cpu,
                                      scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // SALU: wait/delay/clause instructions
    // TODO: Migrate to specific opcode checks (e.g., S_WAIT_LOADCNT) once
    // we have a canonical opcode set for all wait variants.
    if (tsflags & llvm::SIInstrFlags::SALU) {
      auto r = HandleWaitInstruction(line, mnemonic, source_cpu, target_cpu,
                                     scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // Unsupported / skip patterns (category-independent: handles ttmp refs,
    // s_code_end, s_endpgm, s_barrier_*, etc.)
    {
      auto r = HandleUnsupportedInstruction(line, mnemonic, source_cpu, target_cpu,
                                            scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // SMRD: scalar memory read
    if (tsflags & llvm::SIInstrFlags::SMRD) {
      auto r = HandleSMEMInstruction(line, mnemonic, source_cpu, target_cpu,
                                     scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // SALU | VALU: scalar float emulation (includes v_s_sqrt_f32 which is VALU)
    if (tsflags & (llvm::SIInstrFlags::SALU | llvm::SIInstrFlags::VALU)) {
      auto r = HandleSALUFloat(line, mnemonic, source_cpu, target_cpu,
                               scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // VALU: 64-bit operations
    if (tsflags & llvm::SIInstrFlags::VALU) {
      auto r = Handle64BitVALU(line, mnemonic, source_cpu, target_cpu,
                               scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // VALU: constant bus fix
    if (tsflags & llvm::SIInstrFlags::VALU) {
      auto r = HandleConstantBusFix(line, mnemonic, source_cpu, target_cpu,
                                    scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // VOPD: dual-issue instructions
    if ((tsflags & llvm::SIInstrFlags::VOPD3) || mnemonic.find("v_dual_") == 0) {
      auto r = HandleVOPDInstruction(line, mnemonic, source_cpu, target_cpu,
                                     scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

    // WMMA: matrix operations
    if (tsflags & llvm::SIInstrFlags::IsWMMA) {
      auto r = HandleWMMAInstruction(line, mnemonic, source_cpu, target_cpu,
                                     scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }

  } else {
    // String-based fallback dispatch (for recursive VOPD calls without opcode)
    using HandlerFn = TranslationResult (*)(
        const std::string&, const std::string&, const std::string&,
        const std::string&, int, int, bool);

    static const struct { const char* name; HandlerFn handler; } kHandlers[] = {
      {"bitop",         HandleBitopInstruction},
      {"wait",          HandleWaitInstruction},
      {"unsupported",   HandleUnsupportedInstruction},
      {"smem",          HandleSMEMInstruction},
      {"salu_float",    HandleSALUFloat},
      {"64bit_valu",    Handle64BitVALU},
      {"constant_bus",  HandleConstantBusFix},
      {"vopd",          HandleVOPDInstruction},
      {"wmma",          HandleWMMAInstruction},
    };

    for (const auto& h : kHandlers) {
      auto r = h.handler(line, mnemonic, source_cpu, target_cpu,
                         scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
      if (r.has_value()) return *r;
    }
  }

  // Memory handler may modify line/mnemonic (scale_offset)
  {
    auto r = HandleMemoryInstruction(line, mnemonic, source_cpu, target_cpu,
                                     scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
    if (r.has_value()) return *r;
  }

  // ExecOperation handler (v_div_scale null→vcc side effect)
  {
    auto r = HandleExecOperation(line, mnemonic, source_cpu, target_cpu,
                                 scale_temp_vgpr, cmpx_temp_sgpr, compact_mode);
    if (r.has_value()) return *r;
  }

  // ── Post-dispatch: common transforms ──

  // Strip bitop3: modifier from non-v_bitop instructions (GFX12 allows bitop3
  // on regular VALU like v_and_b32_e32; GFX9 does not understand this modifier)
  if (line.find("bitop3:") != std::string::npos && mnemonic.find("v_bitop") != 0) {
    size_t bp = line.find("bitop3:");
    size_t bp_start = bp;
    if (bp_start > 0 && line[bp_start - 1] == ' ') --bp_start;
    size_t bp_end = bp + 7;
    while (bp_end < line.size() && (std::isxdigit(line[bp_end]) ||
           line[bp_end] == 'x' || line[bp_end] == 'X'))
      ++bp_end;
    line.erase(bp_start, bp_end - bp_start);
  }

  // Remaining _nc_ cleanup
  if (mnemonic.find("_nc_") != std::string::npos && mnemonic[0] == 'v') {
    std::string fixed_mnem = mnemonic;
    size_t nc_pos = fixed_mnem.find("_nc_");
    fixed_mnem.replace(nc_pos, 4, "_");
    line = TranspileReplaceMnemonic(line, mnemonic, fixed_mnem);
    mnemonic = fixed_mnem;
  }

  // Unsupported final check
  if (IsUnsupportedOnGFX9(mnemonic)) {
    result.push_back("s_nop 0 ; UNSUPPORTED: " + mnemonic);
    return result;
  }

  // Flat+saddr → Global conversion
  {
    bool is_flat_with_saddr = false;
    if (mnemonic.find("flat_load_") == 0 || mnemonic.find("flat_store_") == 0) {
      size_t s_bracket = line.find("s[", line.find(mnemonic) + mnemonic.size());
      if (s_bracket != std::string::npos) is_flat_with_saddr = true;
    }
    if (is_flat_with_saddr) {
      size_t flat_pos = mnemonic.find("flat_");
      if (flat_pos != std::string::npos) {
        std::string global_mnemonic = "global_" + mnemonic.substr(flat_pos + 5);
        line = TranspileReplaceMnemonic(line, mnemonic, global_mnemonic);
        mnemonic = global_mnemonic;
      }
    }
  }

  // Mnemonic renaming via table
  const auto& mnem_map = GetMnemonicMap();
  auto it = mnem_map.find(mnemonic);
  if (it != mnem_map.end()) {
    line = TranspileReplaceMnemonic(line, mnemonic, it->second);
    mnemonic = it->second;
  } else {
    std::string base = mnemonic;
    std::string suffix;
    if (base.size() > 4 && base.substr(base.size() - 4) == "_e32") { suffix = "_e32"; base = base.substr(0, base.size() - 4); }
    else if (base.size() > 4 && base.substr(base.size() - 4) == "_e64") { suffix = "_e64"; base = base.substr(0, base.size() - 4); }
    if (!suffix.empty()) {
      it = mnem_map.find(base);
      bool is_vop3_only = suffix == "_e32" &&
                 (base.find("_f64") != std::string::npos ||
                  base.find("_b64") != std::string::npos ||
                  base.find("_i64") != std::string::npos ||
                  base.find("_u64") != std::string::npos ||
                  base.find("_f16") != std::string::npos ||
                  base.find("v_cvt_") == 0 ||
                  base.find("v_pk_") == 0);
      if (it != mnem_map.end()) {
        // For VOP3-only ops on GFX9, don't re-add the e32 suffix after rename
        std::string new_mnem = is_vop3_only ? it->second : (it->second + suffix);
        line = TranspileReplaceMnemonic(line, mnemonic, new_mnem);
        mnemonic = new_mnem;
      } else if (is_vop3_only) {
        // Strip _e32 suffix even when no rename is needed.
        line = TranspileReplaceMnemonic(line, mnemonic, base);
        mnemonic = base;
      }
    }
  }

  // Handle v_cvt_f32_f16 with .h source: extract high f16 half before conversion
  if ((mnemonic == "v_cvt_f32_f16_e32" || mnemonic == "v_cvt_f32_f16") &&
      line.find(".h") != std::string::npos) {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 2) {
      std::string dst = operands[0];
      std::string src = operands[1];
      if (src.size() > 2 && src.substr(src.size() - 2) == ".h" &&
          src[0] == 'v' && std::isdigit((unsigned char)src[1])) {
        std::string src_reg = src.substr(0, src.size() - 2);
        result.push_back("v_lshrrev_b32_e32 " + dst + ", 16, " + src_reg);
        line = mnemonic + " " + dst + ", " + dst;
      }
    }
  }

  // Operand syntax translation
  line = TranslateOperandSyntax(line, mnemonic);

  // v_cmp / v_cmpx wave64 expansion
  if (HandleVCmpExpansion(line, mnemonic, result, scale_temp_vgpr, cmpx_temp_sgpr, compact_mode))
    return result;

  // VCC width translation
  bool is_b32_scalar = (mnemonic.find("_b32") != std::string::npos && mnemonic[0] == 's');
  if (!is_b32_scalar)
    line = WidenVccReferences(line);
  if (is_b32_scalar) {
    size_t mnem_end = line.find_first_of(" \t");
    if (mnem_end != std::string::npos) {
      std::string ops_part = line.substr(mnem_end);
      size_t pos = 0;
      while ((pos = ops_part.find("vcc", pos)) != std::string::npos) {
        size_t end = pos + 3;
        if (end < ops_part.size() && ops_part[end] == '_') { pos = end; continue; }
        ops_part.replace(pos, 3, "vcc_lo");
        pos += 6;
      }
      line = line.substr(0, mnem_end) + ops_part;
    }
  }

  // General constant bus fix: catch any VALU with two distinct SGPR sources
  if (mnemonic[0] == 'v' && mnemonic.find("v_readfirstlane") != 0 &&
      mnemonic.find("v_writelane") != 0 && mnemonic.find("v_readlane") != 0) {
    auto operands = ParseOperandList(line, mnemonic);
    if (operands.size() >= 3) {
      auto isSGPR = [](const std::string& op) -> bool {
        std::string s = op;
        if (!s.empty() && s[0] == '-') s = s.substr(1);
        if (!s.empty() && s[0] == '|') s = s.substr(1);
        return !s.empty() && s[0] == 's' && s.size() > 1 &&
               (std::isdigit((unsigned char)s[1]) || s[1] == '[');
      };
      auto sgprBase = [](const std::string& op) -> std::string {
        std::string s = op;
        if (!s.empty() && (s[0] == '-' || s[0] == '|')) s = s.substr(1);
        if (s.find('[') != std::string::npos) return s.substr(0, s.find(']') + 1);
        size_t e = 1;
        while (e < s.size() && std::isdigit((unsigned char)s[e])) ++e;
        return s.substr(0, e);
      };
      std::string first_sgpr;
      for (size_t i = 1; i < operands.size(); ++i) {
        if (isSGPR(operands[i])) {
          std::string base = sgprBase(operands[i]);
          if (first_sgpr.empty()) { first_sgpr = base; }
          else if (base != first_sgpr) {
            const std::string vtemp_fix = "v" + std::to_string(scale_temp_vgpr);
            std::string op = operands[i];
            bool neg = !op.empty() && op[0] == '-';
            if (neg) op = op.substr(1);
            result.push_back("v_mov_b32_e32 " + vtemp_fix + ", " + op);
            operands[i] = (neg ? "-" : "") + vtemp_fix;
            std::string fixed = mnemonic + " " + operands[0];
            for (size_t j = 1; j < operands.size(); ++j) fixed += ", " + operands[j];
            line = fixed;
            break;
          }
        }
      }
    }
  }

  // EXEC width adaptation (wave32 → wave64)
  auto exec_result = WidenExecOperation(line, compact_mode);
  for (auto& l : exec_result)
    result.push_back(std::move(l));
  return result;
}
