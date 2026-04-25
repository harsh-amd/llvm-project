//===- comgr-hotswap-transpiler-tables.cpp - Mnemonic mapping tables ------===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

// ── NeedsTranspile ───────────────────────────────────────────────────────────

bool NeedsTranspileImpl(const std::string &source_isa,
                               const std::string &target_isa) {
  std::string src_cpu = ExtractCPU(source_isa);
  std::string tgt_cpu = ExtractCPU(target_isa);
  if (src_cpu.empty() || tgt_cpu.empty()) return false;
  auto isGFX9 = [](const std::string &cpu) {
    return cpu.size() >= 4 && cpu[3] == '9';
  };
  auto isGFX12 = [](const std::string &cpu) {
    return cpu.size() >= 5 && cpu[3] == '1' && cpu[4] == '2';
  };
  return isGFX12(src_cpu) && isGFX9(tgt_cpu);
}

// ── Mnemonic Translation Tables ──────────────────────────────────────────────
// LEGACY: These tables are used by the text-based fallback path in
// TranslateInstruction (mnemonic renaming in post-dispatch transforms).
// They will be removed when handler implementations are fully migrated to
// MCInst-level translation, at which point OpcodeMapper handles renaming.

static const MnemonicMapping kGlobalMemMappings[] = {
    {"global_load_b32", "global_load_dword"},
    {"global_load_b64", "global_load_dwordx2"},
    {"global_load_b96", "global_load_dwordx3"},
    {"global_load_b128", "global_load_dwordx4"},
    {"global_load_u8", "global_load_ubyte"},
    {"global_load_i8", "global_load_sbyte"},
    {"global_load_u16", "global_load_ushort"},
    {"global_load_i16", "global_load_sshort"},
    {"global_load_d16_u8", "global_load_ubyte_d16"},
    {"global_load_d16_i8", "global_load_sbyte_d16"},
    {"global_load_d16_b16", "global_load_short_d16"},
    {"global_load_d16_hi_u8", "global_load_ubyte_d16_hi"},
    {"global_load_d16_hi_i8", "global_load_sbyte_d16_hi"},
    {"global_load_d16_hi_b16", "global_load_short_d16_hi"},
    {"global_store_b8", "global_store_byte"},
    {"global_store_b16", "global_store_short"},
    {"global_store_b32", "global_store_dword"},
    {"global_store_b64", "global_store_dwordx2"},
    {"global_store_b96", "global_store_dwordx3"},
    {"global_store_b128", "global_store_dwordx4"},
    {"global_load_addtid_b32", "global_load_dword_addtid"},
    {"global_store_addtid_b32", "global_store_dword_addtid"},
};

static const MnemonicMapping kFlatMemMappings[] = {
    {"flat_load_b32", "flat_load_dword"},
    {"flat_load_b64", "flat_load_dwordx2"},
    {"flat_load_b96", "flat_load_dwordx3"},
    {"flat_load_b128", "flat_load_dwordx4"},
    {"flat_load_u8", "flat_load_ubyte"},
    {"flat_load_i8", "flat_load_sbyte"},
    {"flat_load_u16", "flat_load_ushort"},
    {"flat_load_i16", "flat_load_sshort"},
    {"flat_load_d16_u8", "flat_load_ubyte_d16"},
    {"flat_load_d16_i8", "flat_load_sbyte_d16"},
    {"flat_load_d16_b16", "flat_load_short_d16"},
    {"flat_load_d16_hi_u8", "flat_load_ubyte_d16_hi"},
    {"flat_load_d16_hi_i8", "flat_load_sbyte_d16_hi"},
    {"flat_load_d16_hi_b16", "flat_load_short_d16_hi"},
    {"flat_store_b8", "flat_store_byte"},
    {"flat_store_b16", "flat_store_short"},
    {"flat_store_b32", "flat_store_dword"},
    {"flat_store_b64", "flat_store_dwordx2"},
    {"flat_store_b96", "flat_store_dwordx3"},
    {"flat_store_b128", "flat_store_dwordx4"},
};

static const MnemonicMapping kScratchMemMappings[] = {
    {"scratch_load_b32", "scratch_load_dword"},
    {"scratch_load_b64", "scratch_load_dwordx2"},
    {"scratch_load_b96", "scratch_load_dwordx3"},
    {"scratch_load_b128", "scratch_load_dwordx4"},
    {"scratch_load_u8", "scratch_load_ubyte"},
    {"scratch_load_i8", "scratch_load_sbyte"},
    {"scratch_load_u16", "scratch_load_ushort"},
    {"scratch_load_i16", "scratch_load_sshort"},
    {"scratch_load_d16_u8", "scratch_load_ubyte_d16"},
    {"scratch_load_d16_i8", "scratch_load_sbyte_d16"},
    {"scratch_load_d16_b16", "scratch_load_short_d16"},
    {"scratch_load_d16_hi_u8", "scratch_load_ubyte_d16_hi"},
    {"scratch_load_d16_hi_i8", "scratch_load_sbyte_d16_hi"},
    {"scratch_load_d16_hi_b16", "scratch_load_short_d16_hi"},
    {"scratch_store_b8", "scratch_store_byte"},
    {"scratch_store_b16", "scratch_store_short"},
    {"scratch_store_b32", "scratch_store_dword"},
    {"scratch_store_b64", "scratch_store_dwordx2"},
    {"scratch_store_b96", "scratch_store_dwordx3"},
    {"scratch_store_b128", "scratch_store_dwordx4"},
};

static const MnemonicMapping kBufferMemMappings[] = {
    {"buffer_load_b32", "buffer_load_dword"},
    {"buffer_load_b64", "buffer_load_dwordx2"},
    {"buffer_load_b96", "buffer_load_dwordx3"},
    {"buffer_load_b128", "buffer_load_dwordx4"},
    {"buffer_load_u8", "buffer_load_ubyte"},
    {"buffer_load_i8", "buffer_load_sbyte"},
    {"buffer_load_u16", "buffer_load_ushort"},
    {"buffer_load_i16", "buffer_load_sshort"},
    {"buffer_load_d16_u8", "buffer_load_ubyte_d16"},
    {"buffer_load_d16_i8", "buffer_load_sbyte_d16"},
    {"buffer_load_d16_b16", "buffer_load_short_d16"},
    {"buffer_load_d16_hi_u8", "buffer_load_ubyte_d16_hi"},
    {"buffer_load_d16_hi_i8", "buffer_load_sbyte_d16_hi"},
    {"buffer_load_d16_hi_b16", "buffer_load_short_d16_hi"},
    {"buffer_store_b8", "buffer_store_byte"},
    {"buffer_store_b16", "buffer_store_short"},
    {"buffer_store_b32", "buffer_store_dword"},
    {"buffer_store_b64", "buffer_store_dwordx2"},
    {"buffer_store_b96", "buffer_store_dwordx3"},
    {"buffer_store_b128", "buffer_store_dwordx4"},
};

static const MnemonicMapping kDSMappings[] = {
    {"ds_load_b32", "ds_read_b32"},
    {"ds_load_b64", "ds_read_b64"},
    {"ds_load_b96", "ds_read_b96"},
    {"ds_load_b128", "ds_read_b128"},
    {"ds_load_u8", "ds_read_u8"},
    {"ds_load_i8", "ds_read_i8"},
    {"ds_load_u16", "ds_read_u16"},
    {"ds_load_i16", "ds_read_i16"},
    {"ds_load_2addr_b32", "ds_read2_b32"},
    {"ds_load_2addr_stride64_b32", "ds_read2st64_b32"},
    {"ds_load_2addr_b64", "ds_read2_b64"},
    {"ds_load_2addr_stride64_b64", "ds_read2st64_b64"},
    {"ds_load_u8_d16", "ds_read_u8_d16"},
    {"ds_load_i8_d16", "ds_read_i8_d16"},
    {"ds_load_u16_d16", "ds_read_u16_d16"},
    {"ds_load_u8_d16_hi", "ds_read_u8_d16_hi"},
    {"ds_load_i8_d16_hi", "ds_read_i8_d16_hi"},
    {"ds_load_u16_d16_hi", "ds_read_u16_d16_hi"},
    {"ds_load_addtid_b32", "ds_read_addtid_b32"},
    {"ds_store_b32", "ds_write_b32"},
    {"ds_store_b64", "ds_write_b64"},
    {"ds_store_b128", "ds_write_b128"},
    {"ds_store_2addr_b32", "ds_write2_b32"},
    {"ds_store_2addr_stride64_b32", "ds_write2st64_b32"},
    {"ds_store_b8", "ds_write_b8"},
    {"ds_store_b16", "ds_write_b16"},
};

static const MnemonicMapping kSMEMMappings[] = {
    {"s_load_b32", "s_load_dword"},
    {"s_load_b64", "s_load_dwordx2"},
    {"s_load_b96", "s_load_dwordx3"},
    {"s_load_b128", "s_load_dwordx4"},
    {"s_load_b256", "s_load_dwordx8"},
    {"s_load_b512", "s_load_dwordx16"},
    {"s_store_b32", "s_store_dword"},
    {"s_store_b64", "s_store_dwordx2"},
    {"s_store_b128", "s_store_dwordx4"},
    {"s_buffer_load_b32", "s_buffer_load_dword"},
    {"s_buffer_load_b64", "s_buffer_load_dwordx2"},
    {"s_buffer_load_b128", "s_buffer_load_dwordx4"},
    {"s_buffer_load_b256", "s_buffer_load_dwordx8"},
    {"s_buffer_load_b512", "s_buffer_load_dwordx16"},
};

static const MnemonicMapping kScalarALURenames[] = {
    {"s_add_co_u32", "s_add_u32"},
    {"s_sub_co_u32", "s_sub_u32"},
    {"s_add_co_ci_u32", "s_addc_u32"},
    {"s_sub_co_ci_u32", "s_subb_u32"},
    {"s_add_co_i32", "s_add_i32"},
    {"s_sub_co_i32", "s_sub_i32"},
    {"s_and_not1_b32", "s_andn2_b32"},
    {"s_and_not1_b64", "s_andn2_b64"},
    {"s_or_not1_b32", "s_orn2_b32"},
    {"s_or_not1_b64", "s_orn2_b64"},
    {"s_ctz_i32_b32", "s_ff1_i32_b32"},
    {"s_ctz_i32_b64", "s_ff1_i32_b64"},
    {"s_clz_i32_u32", "s_flbit_i32_b32"},
    {"s_clz_i32_u64", "s_flbit_i32_b64"},
    {"s_set_pc_i64", "s_setpc_b64"},
    {"s_swap_pc_i64", "s_swappc_b64"},
    {"s_get_pc_i64", "s_getpc_b64"},
};

static const MnemonicMapping kVALURenames[] = {
    {"v_max_num_f32", "v_max_f32"},
    {"v_min_num_f32", "v_min_f32"},
    {"v_max_num_f16", "v_max_f16"},
    {"v_min_num_f16", "v_min_f16"},
    {"v_max_num_f64", "v_max_f64"},
    {"v_min_num_f64", "v_min_f64"},
    {"v_maxmin_num_f32", "v_maxmin_f32"},
    {"v_minmax_num_f32", "v_minmax_f32"},
    {"v_maxmin_num_f16", "v_maxmin_f16"},
    {"v_minmax_num_f16", "v_minmax_f16"},
    {"v_add_nc_u32", "v_add_u32"},
    {"v_sub_nc_u32", "v_sub_u32"},
    {"v_add_nc_i32", "v_add_u32"},
    {"v_sub_nc_i32", "v_sub_u32"},
    {"v_add_co_ci_u32", "v_addc_co_u32"},
    {"v_sub_co_ci_u32", "v_subb_co_u32"},
    {"v_cvt_pk_f16_f32", "v_cvt_pkrtz_f16_f32"},
    {"v_lshlrev_b64", "v_lshlrev_b64"},
    // GFX12 16-bit ops → GFX9 32-bit equivalents
    {"v_xor_b16", "v_xor_b32"},
    {"v_and_b16", "v_and_b32"},
    {"v_or_b16", "v_or_b32"},
    {"v_cndmask_b16", "v_cndmask_b32"},
    {"v_mov_b16", "v_mov_b32"},
    {"v_add_f16_e32", "v_add_f16"},
    {"v_mul_f16_e32", "v_mul_f16"},
};

static const MnemonicMapping kGlobalAtomicRenames[] = {
    {"global_atomic_add_u32", "global_atomic_add"},
    {"global_atomic_sub_u32", "global_atomic_sub"},
    {"global_atomic_and_b32", "global_atomic_and"},
    {"global_atomic_or_b32", "global_atomic_or"},
    {"global_atomic_xor_b32", "global_atomic_xor"},
    {"global_atomic_min_i32", "global_atomic_smin"},
    {"global_atomic_max_i32", "global_atomic_smax"},
    {"global_atomic_min_u32", "global_atomic_umin"},
    {"global_atomic_max_u32", "global_atomic_umax"},
    {"global_atomic_swap_b32", "global_atomic_swap"},
    {"global_atomic_cmpswap_b32", "global_atomic_cmpswap"},
    {"global_atomic_add_u64", "global_atomic_add_x2"},
    {"global_atomic_sub_u64", "global_atomic_sub_x2"},
    {"global_atomic_and_b64", "global_atomic_and_x2"},
    {"global_atomic_or_b64", "global_atomic_or_x2"},
    {"global_atomic_xor_b64", "global_atomic_xor_x2"},
    {"global_atomic_swap_b64", "global_atomic_swap_x2"},
    {"global_atomic_cmpswap_b64", "global_atomic_cmpswap_x2"},
    {"global_atomic_add_f32", "global_atomic_add_f32"},
    {"global_atomic_pk_add_f16", "global_atomic_pk_add_f16"},
};

static const MnemonicMapping kFlatAtomicRenames[] = {
    {"flat_atomic_add_u32", "flat_atomic_add"},
    {"flat_atomic_sub_u32", "flat_atomic_sub"},
    {"flat_atomic_and_b32", "flat_atomic_and"},
    {"flat_atomic_or_b32", "flat_atomic_or"},
    {"flat_atomic_xor_b32", "flat_atomic_xor"},
    {"flat_atomic_min_i32", "flat_atomic_smin"},
    {"flat_atomic_max_i32", "flat_atomic_smax"},
    {"flat_atomic_min_u32", "flat_atomic_umin"},
    {"flat_atomic_max_u32", "flat_atomic_umax"},
    {"flat_atomic_swap_b32", "flat_atomic_swap"},
    {"flat_atomic_cmpswap_b32", "flat_atomic_cmpswap"},
    {"flat_atomic_add_u64", "flat_atomic_add_x2"},
    {"flat_atomic_sub_u64", "flat_atomic_sub_x2"},
    {"flat_atomic_swap_b64", "flat_atomic_swap_x2"},
    {"flat_atomic_cmpswap_b64", "flat_atomic_cmpswap_x2"},
};

static const MnemonicMapping kDSAtomicRenames[] = {
    {"ds_add_u32", "ds_add_u32"},
    {"ds_add_rtn_u32", "ds_add_rtn_u32"},
    {"ds_cmpstore_b32", "ds_cmpst_b32"},
    {"ds_cmpstore_rtn_b32", "ds_cmpst_rtn_b32"},
    {"ds_cmpstore_b64", "ds_cmpst_b64"},
    {"ds_cmpstore_rtn_b64", "ds_cmpst_rtn_b64"},
};

static std::unordered_map<std::string, std::string> BuildMnemonicMap() {
  std::unordered_map<std::string, std::string> map;
  auto addMappings = [&](const MnemonicMapping* mappings, size_t count) {
    for (size_t i = 0; i < count; ++i)
      map[mappings[i].gfx12] = mappings[i].gfx9;
  };
  addMappings(kGlobalMemMappings, std::size(kGlobalMemMappings));
  addMappings(kFlatMemMappings, std::size(kFlatMemMappings));
  addMappings(kScratchMemMappings, std::size(kScratchMemMappings));
  addMappings(kBufferMemMappings, std::size(kBufferMemMappings));
  addMappings(kDSMappings, std::size(kDSMappings));
  addMappings(kSMEMMappings, std::size(kSMEMMappings));
  addMappings(kScalarALURenames, std::size(kScalarALURenames));
  addMappings(kVALURenames, std::size(kVALURenames));
  addMappings(kGlobalAtomicRenames, std::size(kGlobalAtomicRenames));
  addMappings(kFlatAtomicRenames, std::size(kFlatAtomicRenames));
  addMappings(kDSAtomicRenames, std::size(kDSAtomicRenames));
  return map;
}

const std::unordered_map<std::string, std::string>& GetMnemonicMap() {
  static auto map = BuildMnemonicMap();
  return map;
}
