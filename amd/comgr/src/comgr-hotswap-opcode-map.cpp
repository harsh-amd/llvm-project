//===- comgr-hotswap-opcode-map.cpp - MCInst opcode cross-ISA mapping -----===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

using namespace llvm;

void OpcodeMapper::init(unsigned src_gen) {
  for (unsigned pseudo = 0; pseudo < AMDGPU::INSTRUCTION_LIST_END; ++pseudo) {
    int32_t real = AMDGPU::getMCOpcode(pseudo, src_gen);
    if (real != -1 &&
        real != static_cast<int32_t>(AMDGPU::INSTRUCTION_LIST_END)) {
      real_to_pseudo[static_cast<unsigned>(real)] = pseudo;
    }
  }
}

unsigned OpcodeMapper::toPseudo(unsigned real_opcode) const {
  auto it = real_to_pseudo.find(real_opcode);
  if (it != real_to_pseudo.end())
    return it->second;
  return real_opcode; // pseudo opcodes map to themselves
}

unsigned OpcodeMapper::toTarget(unsigned pseudo_opcode, unsigned tgt_gen) {
  int32_t real = AMDGPU::getMCOpcode(pseudo_opcode, tgt_gen);
  if (real == -1 ||
      real == static_cast<int32_t>(AMDGPU::INSTRUCTION_LIST_END))
    return static_cast<unsigned>(-1);
  return static_cast<unsigned>(real);
}

unsigned GetEncodingFamily(const std::string &cpu) {
  if (cpu.find("gfx9") == 0)  return SIEncodingFamily::VI;
  if (cpu.find("gfx10") == 0) return SIEncodingFamily::GFX10;
  if (cpu == "gfx1250")       return SIEncodingFamily::GFX1250;
  if (cpu.find("gfx12") == 0) return SIEncodingFamily::GFX12;
  if (cpu.find("gfx13") == 0) return SIEncodingFamily::GFX13;
  if (cpu.find("gfx11") == 0) return SIEncodingFamily::GFX11;
  return SIEncodingFamily::VI; // default
}

static std::mutex g_mapper_mutex;
static std::unordered_map<unsigned, OpcodeMapper> g_mappers;

OpcodeMapper &GetOpcodeMapper(unsigned src_gen) {
  std::lock_guard<std::mutex> lock(g_mapper_mutex);
  auto it = g_mappers.find(src_gen);
  if (it != g_mappers.end())
    return it->second;
  g_mappers[src_gen].init(src_gen);
  return g_mappers[src_gen];
}
