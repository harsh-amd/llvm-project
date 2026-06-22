//===- comgr-hotswap-entry-trampoline.cpp - Kernel-entry stubs ------------===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Opt-in kernel-entry redirection pass for COMGR HotSwap. This pass is
/// independent of the gfx1250 B0-to-A0 instruction patcher: it appends one
/// PC-relative entry stub per kernel descriptor and rewrites the descriptor's
/// kernel_code_entry_byte_offset to point at that stub.
///
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Alignment.h"

using namespace llvm;

namespace COMGR {
namespace hotswap {

static bool appendAsm(SmallVectorImpl<uint8_t> &Out, StringRef Asm,
                      const LLVMState &LS) {
  SmallVector<uint8_t> Bytes = assembleSingleInst(Asm, LS);
  if (Bytes.empty()) {
    log() << "hotswap: error: failed to assemble entry-stub instruction: "
          << Asm << "\n";
    return false;
  }
  Out.append(Bytes.begin(), Bytes.end());
  return true;
}

SmallVector<uint8_t> buildKernelEntryTrampoline(uint64_t StubVAddr,
                                                uint64_t EntryVAddr,
                                                const LLVMState &LS) {
  SmallVector<uint8_t> Bytes;

  // Assemble through the MC layer instead of spelling encoded bytes; the LIT
  // test pins the generated stub's disassembly.
  if (!appendAsm(Bytes, "global_wb", LS))
    return {};
  if (!appendAsm(Bytes, "v_nop", LS))
    return {};
  if (!appendAsm(Bytes, "s_get_pc_i64 s[100:101]", LS))
    return {};

  // s_get_pc_i64 returns the address of the following s_add_u32 instruction.
  // Materialize the original entry with a 64-bit PC-relative add so the code
  // object can be rewritten before ROCR knows final device addresses.
  const uint64_t PcBase = StubVAddr + Bytes.size();
  const uint64_t Delta = EntryVAddr - PcBase;
  const uint32_t Lo = static_cast<uint32_t>(Delta);
  const uint32_t Hi = static_cast<uint32_t>(Delta >> 32);

  if (!appendAsm(Bytes, std::string("s_add_u32 s100, s100, 0x") + utohexstr(Lo),
                 LS))
    return {};
  if (!appendAsm(Bytes,
                 std::string("s_addc_u32 s101, s101, 0x") + utohexstr(Hi), LS))
    return {};
  if (!appendAsm(Bytes, "s_set_pc_i64 s[100:101]", LS))
    return {};

  SmallVector<uint8_t> CodeEnd = assembleSingleInst("s_code_end", LS);
  if (CodeEnd.empty()) {
    log() << "hotswap: error: failed to assemble s_code_end for entry-stub "
          << "padding.\n";
    return {};
  }
  if (Bytes.size() > KernelEntryStubStride) {
    log() << "hotswap: error: kernel-entry stub grew past "
          << KernelEntryStubStride << " bytes.\n";
    return {};
  }
  while (Bytes.size() < KernelEntryStubStride) {
    if (Bytes.size() + CodeEnd.size() > KernelEntryStubStride) {
      log() << "hotswap: error: s_code_end padding does not evenly fill "
            << "kernel-entry stub stride " << KernelEntryStubStride << ".\n";
      return {};
    }
    Bytes.append(CodeEnd.begin(), CodeEnd.end());
  }
  return Bytes;
}

bool isKernelEntryTrampoline(ArrayRef<uint8_t> Bytes, const LLVMState &LS) {
  if (Bytes.size() < KernelEntryStubStride)
    return false;

  if (!LS.MCII || LS.GlobalWbOpcode >= LS.MCII->getNumOpcodes() ||
      LS.SGetPcI64Opcode >= LS.MCII->getNumOpcodes() ||
      LS.SAddU32Opcode >= LS.MCII->getNumOpcodes() ||
      LS.SAddcU32Opcode >= LS.MCII->getNumOpcodes() ||
      LS.SSetPcI64Opcode >= LS.MCII->getNumOpcodes()) {
    log() << "hotswap: error: isKernelEntryTrampoline: LLVMState lacks "
          << "resolved entry-stub opcodes.\n";
    return false;
  }

  std::vector<InternalDecodedInst> Decoded;
  if (!decodeTextSection(Bytes.data(), KernelEntryStubStride, LS, Decoded)) {
    log() << "hotswap: error: isKernelEntryTrampoline: failed to decode "
          << KernelEntryStubStride << "-byte candidate.\n";
    return false;
  }
  if (Decoded.size() < 6)
    return false;

  return Decoded[0].Inst.getOpcode() == LS.GlobalWbOpcode &&
         Decoded[1].Inst.getOpcode() == LS.VNopInst.getOpcode() &&
         Decoded[2].Inst.getOpcode() == LS.SGetPcI64Opcode &&
         Decoded[3].Inst.getOpcode() == LS.SAddU32Opcode &&
         Decoded[4].Inst.getOpcode() == LS.SAddcU32Opcode &&
         Decoded[5].Inst.getOpcode() == LS.SSetPcI64Opcode;
}

bool isKernelEntryDisplacementPrefix(ArrayRef<uint8_t> Bytes,
                                     const LLVMState &LS) {
  if (Bytes.empty())
    return false;

  if (!LS.MCII || LS.GlobalWbOpcode >= LS.MCII->getNumOpcodes()) {
    log() << "hotswap: error: isKernelEntryDisplacementPrefix: LLVMState "
          << "lacks resolved entry-prefix opcodes.\n";
    return false;
  }

  std::vector<InternalDecodedInst> Decoded;
  if (!decodeTextSection(Bytes.data(), Bytes.size(), LS, Decoded)) {
    log() << "hotswap: error: isKernelEntryDisplacementPrefix: failed to "
          << "decode candidate.\n";
    return false;
  }
  if (Decoded.size() < 2)
    return false;

  return Decoded[0].Inst.getOpcode() == LS.GlobalWbOpcode &&
         Decoded[1].Inst.getOpcode() == LS.VNopInst.getOpcode();
}

static SmallVector<uint8_t> buildKernelEntryDisplacementPrefix(
    const LLVMState &LS) {
  SmallVector<uint8_t> Prefix;
  if (!appendAsm(Prefix, "global_wb", LS))
    return {};
  if (!appendAsm(Prefix, "v_nop", LS))
    return {};
  return Prefix;
}

static uint64_t entryVAddr(const KernelDescriptorInfo &KD) {
  return KD.VAddr + static_cast<uint64_t>(KD.EntryOffset);
}

static bool descriptorAlreadyTargetsEntryStub(const ElfView &Elf,
                                              const KernelDescriptorInfo &KD,
                                              const LLVMState &LS) {
  const uint64_t Entry = entryVAddr(KD);
  if (Entry < Elf.textAddr())
    return false;
  const uint64_t TextOffset = Entry - Elf.textAddr();
  SmallVector<uint8_t> Prefix = buildKernelEntryDisplacementPrefix(LS);
  if (!Prefix.empty() && TextOffset + Prefix.size() <= Elf.textSize() &&
      isKernelEntryDisplacementPrefix(
          ArrayRef<uint8_t>(Elf.textData() + TextOffset, Prefix.size()), LS))
    return true;
  if (TextOffset + KernelEntryStubStride > Elf.textSize())
    return false;
  return isKernelEntryTrampoline(
      ArrayRef<uint8_t>(Elf.textData() + TextOffset, KernelEntryStubStride),
      LS);
}

static uint64_t totalTrampolineBytes(ArrayRef<Trampoline> Trampolines) {
  uint64_t Total = 0;
  for (const Trampoline &T : Trampolines)
    Total += T.Bytes.size();
  return Total;
}

static bool appendPaddingTrampoline(std::vector<Trampoline> &Out,
                                    uint64_t PadBytes, ArrayRef<uint8_t> Fill) {
  if (PadBytes == 0)
    return true;
  if (Fill.empty()) {
    log() << "hotswap: error: entry-stub alignment padding requested without "
          << "cached s_nop bytes.\n";
    return false;
  }
  if (PadBytes % Fill.size() != 0) {
    log() << "hotswap: error: entry-stub alignment padding size " << PadBytes
          << " is not a multiple of cached s_nop size " << Fill.size() << ".\n";
    return false;
  }

  Trampoline Pad;
  while (Pad.Bytes.size() < PadBytes)
    Pad.Bytes.append(Fill.begin(), Fill.end());
  Out.push_back(std::move(Pad));
  return true;
}

std::optional<uint32_t> collectKernelEntryDisplacements(
    const ElfView &Elf, const LLVMState &LS,
    std::vector<DisplacementEdit> &OutEdits) {
  std::vector<KernelDescriptorInfo> Descriptors = Elf.kernelDescriptors();
  if (Descriptors.empty())
    return 0;

  SmallVector<uint8_t> Prefix = buildKernelEntryDisplacementPrefix(LS);
  if (Prefix.empty())
    return std::nullopt;

  uint32_t Added = 0;
  for (const KernelDescriptorInfo &KD : Descriptors) {
    if (descriptorAlreadyTargetsEntryStub(Elf, KD, LS))
      continue;

    const uint64_t Entry = entryVAddr(KD);
    if (Entry < Elf.textAddr() || Entry > Elf.textAddr() + Elf.textSize()) {
      log() << "hotswap: error: kernel-entry displacement for '"
            << KD.KernelName << "' points outside .text at vaddr 0x"
            << utohexstr(Entry) << ".\n";
      return std::nullopt;
    }
    const uint64_t TextOffset = Entry - Elf.textAddr();

    bool DuplicateOffset = false;
    for (const DisplacementEdit &Existing : OutEdits) {
      if (Existing.Offset == TextOffset && Existing.OriginalSize == 0) {
        DuplicateOffset = true;
        break;
      }
    }
    if (DuplicateOffset)
      continue;

    DisplacementEdit Edit;
    Edit.Offset = TextOffset;
    Edit.OriginalSize = 0;
    Edit.ReplacementBytes.assign(Prefix.begin(), Prefix.end());
    Edit.KernelName = KD.KernelName;
    OutEdits.push_back(std::move(Edit));
    ++Added;
  }

  if (Added > 0)
    log() << "hotswap: queued " << Added << " kernel-entry displacement"
          << (Added == 1 ? "" : "s") << "\n";
  return Added;
}

std::optional<uint32_t> appendKernelEntryTrampolines(
    const ElfView &Elf, const LLVMState &LS, std::vector<Trampoline> &Growth,
    std::vector<KernelEntryTrampolineFixup> &OutFixups) {
  std::vector<KernelDescriptorInfo> Descriptors = Elf.kernelDescriptors();
  if (Descriptors.empty())
    return 0;

  std::vector<KernelDescriptorInfo> Work;
  for (const KernelDescriptorInfo &KD : Descriptors) {
    if (descriptorAlreadyTargetsEntryStub(Elf, KD, LS))
      continue;
    Work.push_back(KD);
  }
  if (Work.empty())
    return 0;

  uint64_t AppendOffset = totalTrampolineBytes(Growth);
  const uint64_t StubStart =
      alignTo(Elf.textSize() + AppendOffset, Align(KernelEntryStubStride)) -
      Elf.textSize();
  std::vector<Trampoline> LocalGrowth;
  std::vector<KernelEntryTrampolineFixup> LocalFixups;
  if (!appendPaddingTrampoline(LocalGrowth, StubStart - AppendOffset,
                               LS.SNopBytes))
    return std::nullopt;
  AppendOffset = StubStart;

  for (const KernelDescriptorInfo &KD : Work) {
    const uint64_t StubVAddr = Elf.textAddr() + Elf.textSize() + AppendOffset;
    SmallVector<uint8_t> Stub =
        buildKernelEntryTrampoline(StubVAddr, entryVAddr(KD), LS);
    if (Stub.empty()) {
      log() << "hotswap: error: failed to build kernel-entry trampoline for '"
            << KD.KernelName << "' at original entry vaddr 0x"
            << utohexstr(entryVAddr(KD)) << ".\n";
      return std::nullopt;
    }

    Trampoline T;
    T.Bytes.assign(Stub.begin(), Stub.end());
    LocalGrowth.push_back(std::move(T));
    LocalFixups.push_back({KD.KernelName, AppendOffset});
    AppendOffset += KernelEntryStubStride;
  }

  if (LocalFixups.empty())
    return 0;

  for (Trampoline &T : LocalGrowth)
    Growth.push_back(std::move(T));
  OutFixups.insert(OutFixups.end(), LocalFixups.begin(), LocalFixups.end());

  log() << "hotswap: installed " << LocalFixups.size()
        << " kernel-entry trampoline" << (LocalFixups.size() == 1 ? "" : "s")
        << "\n";
  return static_cast<uint32_t>(LocalFixups.size());
}

bool rewriteKernelEntryDescriptorOffsets(
    WritableMemoryBuffer &OutBuf, uint64_t OldTextSize,
    ArrayRef<KernelEntryTrampolineFixup> Fixups, StringRef TargetCpu) {
  if (Fixups.empty())
    return true;

  uint8_t *Data = reinterpret_cast<uint8_t *>(OutBuf.getBufferStart());
  Expected<ElfView> ViewOrErr = ElfView::create(Data, OutBuf.getBufferSize());
  if (!ViewOrErr) {
    log() << "hotswap: error: failed to reparse grown ELF for entry "
          << "descriptor rewrites: " << toString(ViewOrErr.takeError()) << "\n";
    return false;
  }

  bool Ok = true;
  ElfView &OutElf = *ViewOrErr;
  for (const KernelEntryTrampolineFixup &Fixup : Fixups) {
    std::optional<uint64_t> KdVAddr =
        OutElf.getKernelDescriptorVAddr(Fixup.KernelName);
    if (!KdVAddr) {
      log() << "hotswap: error: missing kernel descriptor for entry "
            << "trampoline fixup '" << Fixup.KernelName << "'.\n";
      Ok = false;
      continue;
    }
    const uint64_t StubVAddr =
        OutElf.textAddr() + OldTextSize + Fixup.StubTextOffset;
    const int64_t NewOffset = static_cast<int64_t>(StubVAddr - *KdVAddr);
    Ok &= OutElf.updateKernelDescriptorEntryOffset(Fixup.KernelName, NewOffset);
    Ok &= OutElf.clearKernelDescriptorInstPrefSize(Fixup.KernelName,
                                                   TargetCpu);
  }
  return Ok;
}

} // namespace hotswap
} // namespace COMGR
