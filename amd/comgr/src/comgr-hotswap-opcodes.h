//===- comgr-hotswap-opcodes.h - AMDGPU opcode enums for HotSwap ---------===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Thin wrapper that pulls in AMDGPU opcode enums, register enums, and the
/// getMCOpcode cross-ISA mapping function for use by the hotswap transpiler.
///
//===----------------------------------------------------------------------===//

#ifndef COMGR_HOTSWAP_OPCODES_H
#define COMGR_HOTSWAP_OPCODES_H

#include "SIDefines.h"

#define GET_INSTRINFO_ENUM
#include "AMDGPUGenInstrInfo.inc"

namespace llvm::AMDGPU {
int32_t getMCOpcode(uint32_t Opcode, unsigned Gen);
}

#endif // COMGR_HOTSWAP_OPCODES_H
