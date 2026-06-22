//===- comgr-hotswap-displacement.cpp - HotSwap text displacement --------===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Direct `.text` displacement for HotSwap rewrites. This layer inserts
/// larger replacement sequences into `.text`, shifts the displaced code
/// forward, repairs direct PC-relative scalar branches when it can prove the
/// new encoding, and updates ELF metadata. Appended trampolines remain the
/// fallback when any check fails.
///
//===----------------------------------------------------------------------===//

#include "comgr-hotswap-internal.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/Support/Alignment.h"

#include <algorithm>

using namespace llvm;

namespace COMGR {
namespace hotswap {

using Ehdr = ELF::Elf64_Ehdr;
using Shdr = ELF::Elf64_Shdr;
using Phdr = ELF::Elf64_Phdr;
using ELFT = ElfView::ELFT;
using ELFFileT = ElfView::ELFFileT;

namespace {

Error makeDisplacementError(const Twine &Msg) {
  return createStringError(object::object_error::parse_failed, Msg);
}

void setReason(std::string *Reason, const Twine &Msg) {
  if (Reason)
    *Reason = Msg.str();
}

uint64_t maxPostTextAlignment(const ElfView &Elf) {
  uint64_t MaxAlign = 1;
  for (const ELFT::Shdr &Shdr : Elf.sections()) {
    if (Shdr.sh_offset <= Elf.textOffset())
      continue;
    MaxAlign = std::max<uint64_t>(MaxAlign, Shdr.sh_addralign);
  }
  return std::max<uint64_t>(MaxAlign, 1);
}

bool hasTextRelocations(const ElfView &Elf, std::string *Reason) {
  unsigned SectionIndex = 0;
  for (const ELFT::Shdr &Shdr : Elf.sections()) {
    if (Shdr.sh_type != ELF::SHT_REL && Shdr.sh_type != ELF::SHT_RELA) {
      ++SectionIndex;
      continue;
    }

    if (Shdr.sh_info == Elf.textSectionIndex()) {
      Expected<StringRef> NameOrErr = Elf.file().getSectionName(Shdr);
      std::string Name =
          NameOrErr ? NameOrErr->str() : ("section " + Twine(SectionIndex)).str();
      if (!NameOrErr)
        consumeError(NameOrErr.takeError());
      setReason(Reason, "relocation section '" + Twine(Name) +
                            "' references .text");
      return true;
    }
    ++SectionIndex;
  }
  return false;
}

SmallVector<uint8_t> encodeMCInstBytes(const MCInst &Inst,
                                       const LLVMState &LS) {
  SmallVector<char, 16> Code;
  SmallVector<MCFixup, 4> Fixups;
  LS.MCE->encodeInstruction(Inst, Code, Fixups, *LS.STI);
  return SmallVector<uint8_t>(Code.begin(), Code.end());
}

bool reencodePcrelBranch(const InternalDecodedInst &DI, uint64_t NewFrom,
                         uint64_t NewTarget, const LLVMState &LS,
                         SmallVectorImpl<uint8_t> &Out,
                         std::string *Reason) {
  if (DI.Inst.getOpcode() == LS.SBranchOpcode) {
    Out = LS.encodeSBranch(NewFrom, NewTarget);
    if (Out.empty()) {
      setReason(Reason, "s_branch at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " is out of range after displacement");
      return false;
    }
    return true;
  }

  if (DI.Inst.getNumOperands() == 0 || !DI.Inst.getOperand(0).isImm()) {
    setReason(Reason, "branch at old .text offset 0x" +
                          Twine::utohexstr(DI.Offset) +
                          " does not expose an immediate target operand");
    return false;
  }

  int64_t ByteDelta =
      static_cast<int64_t>(NewTarget) - static_cast<int64_t>(NewFrom) -
      static_cast<int64_t>(DI.Size);
  if (ByteDelta % MinInstSize != 0) {
    setReason(Reason, "branch at old .text offset 0x" +
                          Twine::utohexstr(DI.Offset) +
                          " has unaligned displacement after rewrite");
    return false;
  }

  int64_t DwordOffset = ByteDelta / MinInstSize;
  if (DwordOffset < BranchOffsetMin || DwordOffset > BranchOffsetMax) {
    setReason(Reason, "branch at old .text offset 0x" +
                          Twine::utohexstr(DI.Offset) +
                          " is out of simm16 range after displacement");
    return false;
  }

  MCInst NewInst = DI.Inst;
  NewInst.getOperand(0).setImm(DwordOffset);
  Out = encodeMCInstBytes(NewInst, LS);
  if (Out.size() != DI.Size) {
    setReason(Reason, "branch at old .text offset 0x" +
                          Twine::utohexstr(DI.Offset) +
                          " changed encoded size during re-encode");
    return false;
  }
  return true;
}

bool repairBranches(const ElfView &Elf, const LLVMState &LS,
                    const DisplacementPlan &Plan,
                    SmallVectorImpl<uint8_t> &NewText,
                    std::string *Reason) {
  if (!LS.MIA) {
    setReason(Reason, "LLVM MC branch analysis is unavailable");
    return false;
  }

  std::vector<InternalDecodedInst> Decoded;
  if (!decodeTextSection(Elf.textData(), Elf.textSize(), LS, Decoded)) {
    setReason(Reason, "failed to decode .text while validating branches");
    return false;
  }

  for (const InternalDecodedInst &DI : Decoded) {
    if (Plan.rangeOverlapsReplacement(DI.Offset, DI.Size))
      continue;

    const MCInst &Inst = DI.Inst;
    if (LS.MIA->isCall(Inst)) {
      setReason(Reason, "call at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " is not supported by displacement");
      return false;
    }
    if (LS.MIA->isIndirectBranch(Inst)) {
      setReason(Reason, "indirect branch at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " is not supported by displacement");
      return false;
    }
    if (!LS.MIA->isBranch(Inst))
      continue;

    uint64_t OldTarget = 0;
    if (!LS.MIA->evaluateBranch(Inst, DI.Offset, DI.Size, OldTarget)) {
      setReason(Reason, "branch at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " target could not be evaluated");
      return false;
    }
    if (OldTarget >= Elf.textSize()) {
      setReason(Reason, "branch at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " targets outside .text");
      return false;
    }

    uint64_t NewFrom = 0;
    uint64_t NewTarget = 0;
    if (!Plan.mapOffset(DI.Offset, DisplacementMapBias::AfterInsertedBytes,
                        NewFrom)) {
      setReason(Reason, "branch source at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " maps inside a replaced range");
      return false;
    }
    if (!Plan.mapOffset(OldTarget, DisplacementMapBias::BeforeInsertedBytes,
                        NewTarget)) {
      setReason(Reason, "branch target at old .text offset 0x" +
                            Twine::utohexstr(OldTarget) +
                            " maps inside a replaced range");
      return false;
    }

    SmallVector<uint8_t> Encoded;
    if (!reencodePcrelBranch(DI, NewFrom, NewTarget, LS, Encoded, Reason))
      return false;

    if (NewFrom + Encoded.size() > NewText.size()) {
      setReason(Reason, "re-encoded branch at old .text offset 0x" +
                            Twine::utohexstr(DI.Offset) +
                            " writes past rebuilt .text");
      return false;
    }
    std::memcpy(NewText.data() + NewFrom, Encoded.data(), Encoded.size());
  }
  return true;
}

void adjustSectionHeadersForTextGrowth(uint8_t *Elf, size_t ElfSize,
                                       const ElfView &OldElf,
                                       size_t Growth) {
  if (ElfSize < sizeof(Ehdr))
    return;

  const uint64_t TextOffset = OldElf.textOffset();
  const uint64_t TextSize = OldElf.textSize();
  const uint64_t TextEnd = TextOffset + TextSize;

  uint64_t Shoff = 0;
  uint16_t Shentsize = 0;
  uint16_t Shnum = 0;
  std::memcpy(&Shoff, Elf + offsetof(Ehdr, e_shoff), sizeof(Shoff));
  std::memcpy(&Shentsize, Elf + offsetof(Ehdr, e_shentsize), sizeof(Shentsize));
  std::memcpy(&Shnum, Elf + offsetof(Ehdr, e_shnum), sizeof(Shnum));
  if (Shentsize < sizeof(Shdr))
    return;

  if (Shoff >= TextEnd) {
    uint64_t NewShoff = Shoff + Growth;
    std::memcpy(Elf + offsetof(Ehdr, e_shoff), &NewShoff, sizeof(NewShoff));
    Shoff = NewShoff;
  }

  for (uint16_t I = 0; I < Shnum; ++I) {
    uint64_t ShPos = Shoff + static_cast<uint64_t>(I) * Shentsize;
    if (ShPos + sizeof(Shdr) > ElfSize)
      break;
    uint8_t *Sh = Elf + ShPos;
    uint64_t ShOffset = 0;
    std::memcpy(&ShOffset, Sh + offsetof(Shdr, sh_offset), sizeof(ShOffset));

    if (ShOffset == TextOffset) {
      uint64_t NewTextSize = TextSize + Growth;
      std::memcpy(Sh + offsetof(Shdr, sh_size), &NewTextSize,
                  sizeof(NewTextSize));
    } else if (ShOffset > TextOffset) {
      uint64_t NewOffset = ShOffset + Growth;
      std::memcpy(Sh + offsetof(Shdr, sh_offset), &NewOffset,
                  sizeof(NewOffset));
      uint64_t ShFlags = 0;
      std::memcpy(&ShFlags, Sh + offsetof(Shdr, sh_flags), sizeof(ShFlags));
      if (ShFlags & ELF::SHF_ALLOC) {
        uint64_t ShAddr = 0;
        std::memcpy(&ShAddr, Sh + offsetof(Shdr, sh_addr), sizeof(ShAddr));
        ShAddr += Growth;
        std::memcpy(Sh + offsetof(Shdr, sh_addr), &ShAddr, sizeof(ShAddr));
      }
    }
  }
}

void adjustProgramHeadersForTextGrowth(uint8_t *Elf, size_t ElfSize,
                                       const ElfView &OldElf,
                                       size_t Growth) {
  if (ElfSize < sizeof(Ehdr))
    return;

  const uint64_t TextOffset = OldElf.textOffset();
  const uint64_t TextEnd = TextOffset + OldElf.textSize();

  uint64_t Phoff = 0;
  uint16_t Phentsize = 0;
  uint16_t Phnum = 0;
  std::memcpy(&Phoff, Elf + offsetof(Ehdr, e_phoff), sizeof(Phoff));
  std::memcpy(&Phentsize, Elf + offsetof(Ehdr, e_phentsize), sizeof(Phentsize));
  std::memcpy(&Phnum, Elf + offsetof(Ehdr, e_phnum), sizeof(Phnum));
  if (Phentsize < sizeof(Phdr))
    return;

  for (uint16_t I = 0; I < Phnum; ++I) {
    uint64_t PhPos = Phoff + static_cast<uint64_t>(I) * Phentsize;
    if (PhPos + sizeof(Phdr) > ElfSize)
      break;
    uint8_t *Ph = Elf + PhPos;
    uint64_t POffset = 0;
    uint64_t PFilesz = 0;
    uint64_t PMemsz = 0;
    std::memcpy(&POffset, Ph + offsetof(Phdr, p_offset), sizeof(POffset));
    std::memcpy(&PFilesz, Ph + offsetof(Phdr, p_filesz), sizeof(PFilesz));
    std::memcpy(&PMemsz, Ph + offsetof(Phdr, p_memsz), sizeof(PMemsz));

    if (POffset <= TextOffset && POffset + PFilesz >= TextEnd) {
      PFilesz += Growth;
      PMemsz += Growth;
      std::memcpy(Ph + offsetof(Phdr, p_filesz), &PFilesz, sizeof(PFilesz));
      std::memcpy(Ph + offsetof(Phdr, p_memsz), &PMemsz, sizeof(PMemsz));
    } else if (POffset > TextOffset) {
      POffset += Growth;
      std::memcpy(Ph + offsetof(Phdr, p_offset), &POffset, sizeof(POffset));
      uint64_t PVaddr = 0;
      std::memcpy(&PVaddr, Ph + offsetof(Phdr, p_vaddr), sizeof(PVaddr));
      PVaddr += Growth;
      std::memcpy(Ph + offsetof(Phdr, p_vaddr), &PVaddr, sizeof(PVaddr));
      uint64_t PPaddr = 0;
      std::memcpy(&PPaddr, Ph + offsetof(Phdr, p_paddr), sizeof(PPaddr));
      PPaddr += Growth;
      std::memcpy(Ph + offsetof(Phdr, p_paddr), &PPaddr, sizeof(PPaddr));
    }
  }
}

bool mapTextSymbolValue(const ELFT::Sym &Sym, const ELFT::Shdr &DefShdr,
                        const DisplacementPlan &Plan, uint64_t &NewValue,
                        uint64_t &OldOffset) {
  const bool LooksLikeVAddr = Sym.st_value >= DefShdr.sh_addr &&
                              Sym.st_value - DefShdr.sh_addr <=
                                  Plan.oldTextSize();
  OldOffset = LooksLikeVAddr ? Sym.st_value - DefShdr.sh_addr : Sym.st_value;
  if (OldOffset > Plan.oldTextSize())
    return false;

  uint64_t NewOffset = 0;
  if (!Plan.mapOffset(OldOffset, DisplacementMapBias::BeforeInsertedBytes,
                      NewOffset))
    return false;
  NewValue = LooksLikeVAddr ? DefShdr.sh_addr + NewOffset : NewOffset;
  return true;
}

bool adjustSymbolValuesForDisplacement(uint8_t *Elf, size_t ElfSize,
                                       const ElfView &OldElf,
                                       const DisplacementPlan &Plan,
                                       std::string *Reason) {
  Expected<ELFFileT> FileOrErr =
      ELFFileT::create(StringRef(reinterpret_cast<const char *>(Elf), ElfSize));
  if (!FileOrErr) {
    setReason(Reason, "failed to parse displaced ELF for symbol repair: " +
                          Twine(toString(FileOrErr.takeError())));
    return false;
  }
  ELFFileT File = std::move(*FileOrErr);

  Expected<ELFT::ShdrRange> SectionsOrErr = File.sections();
  if (!SectionsOrErr) {
    setReason(Reason, "failed to read displaced ELF sections for symbol repair: " +
                          Twine(toString(SectionsOrErr.takeError())));
    return false;
  }
  ELFT::ShdrRange Sections = *SectionsOrErr;

  for (const ELFT::Shdr &SymShdr : Sections) {
    if (SymShdr.sh_type != ELF::SHT_SYMTAB &&
        SymShdr.sh_type != ELF::SHT_DYNSYM)
      continue;

    Expected<ELFT::SymRange> SymsOrErr = File.symbols(&SymShdr);
    if (!SymsOrErr) {
      setReason(Reason, "failed to read symbol table during displacement");
      return false;
    }

    for (const ELFT::Sym &Sym : *SymsOrErr) {
      if (Sym.st_shndx == ELF::SHN_UNDEF || Sym.st_shndx >= ELF::SHN_LORESERVE)
        continue;

      Expected<const ELFT::Shdr *> DefShdrOrErr = File.getSection(Sym.st_shndx);
      if (!DefShdrOrErr) {
        consumeError(DefShdrOrErr.takeError());
        continue;
      }
      const ELFT::Shdr &DefShdr = **DefShdrOrErr;

      const uint8_t *SymBytes = reinterpret_cast<const uint8_t *>(&Sym);
      if (SymBytes < File.base() || SymBytes + sizeof(ELFT::Sym) > File.end()) {
        setReason(Reason, "symbol table entry is outside displaced ELF buffer");
        return false;
      }
      uint64_t SymOffset = SymBytes - File.base();

      if (Sym.st_shndx == OldElf.textSectionIndex()) {
        uint64_t NewValue = 0;
        uint64_t OldOffset = 0;
        if (!mapTextSymbolValue(Sym, DefShdr, Plan, NewValue, OldOffset)) {
          setReason(Reason, "text symbol maps inside a replaced range");
          return false;
        }
        std::memcpy(Elf + SymOffset + offsetof(ELFT::Sym, st_value),
                    &NewValue, sizeof(NewValue));

        if (Sym.st_size != 0 && OldOffset <= Plan.oldTextSize()) {
          uint64_t OldEnd = OldOffset + Sym.st_size;
          if (OldEnd <= Plan.oldTextSize()) {
            uint64_t NewStart = 0;
            uint64_t NewEnd = 0;
            if (Plan.mapOffset(OldOffset,
                               DisplacementMapBias::BeforeInsertedBytes,
                               NewStart) &&
                Plan.mapOffset(OldEnd,
                               DisplacementMapBias::AfterInsertedBytes,
                               NewEnd) &&
                NewEnd >= NewStart) {
              uint64_t NewSize = NewEnd - NewStart;
              std::memcpy(Elf + SymOffset + offsetof(ELFT::Sym, st_size),
                          &NewSize, sizeof(NewSize));
            }
          }
        }
        continue;
      }

      if (!(DefShdr.sh_flags & ELF::SHF_ALLOC) ||
          DefShdr.sh_offset <= OldElf.textOffset())
        continue;

      uint64_t Value = Sym.st_value + Plan.paddedGrowth();
      std::memcpy(Elf + SymOffset + offsetof(ELFT::Sym, st_value), &Value,
                  sizeof(Value));
    }
  }
  return true;
}

bool rewriteKernelDescriptorEntriesForDisplacement(
    WritableMemoryBuffer &OutBuf, const ElfView &OldElf,
    const DisplacementPlan &Plan, std::string *Reason) {
  uint8_t *Data = reinterpret_cast<uint8_t *>(OutBuf.getBufferStart());
  Expected<ElfView> OutViewOrErr = ElfView::create(Data, OutBuf.getBufferSize());
  if (!OutViewOrErr) {
    setReason(Reason, "failed to reparse displaced ELF for descriptor repair: " +
                          Twine(toString(OutViewOrErr.takeError())));
    return false;
  }

  ElfView &OutElf = *OutViewOrErr;
  for (const KernelDescriptorInfo &KD : OldElf.kernelDescriptors()) {
    const uint64_t OldEntryVAddr =
        KD.VAddr + static_cast<uint64_t>(KD.EntryOffset);
    if (OldEntryVAddr < OldElf.textAddr() ||
        OldEntryVAddr >= OldElf.textAddr() + OldElf.textSize())
      continue;

    uint64_t OldEntryOffset = OldEntryVAddr - OldElf.textAddr();
    uint64_t NewEntryOffset = 0;
    if (!Plan.mapOffset(OldEntryOffset,
                        DisplacementMapBias::BeforeInsertedBytes,
                        NewEntryOffset)) {
      setReason(Reason, "kernel descriptor entry for '" +
                            Twine(KD.KernelName) +
                            "' maps inside a replaced range");
      return false;
    }

    std::optional<uint64_t> NewKdVAddr =
        OutElf.getKernelDescriptorVAddr(KD.KernelName);
    if (!NewKdVAddr) {
      setReason(Reason, "missing kernel descriptor for '" +
                            Twine(KD.KernelName) +
                            "' after displacement");
      return false;
    }

    const uint64_t NewEntryVAddr = OutElf.textAddr() + NewEntryOffset;
    const int64_t NewKdEntryOffset =
        static_cast<int64_t>(NewEntryVAddr - *NewKdVAddr);
    if (!OutElf.updateKernelDescriptorEntryOffset(KD.KernelName,
                                                  NewKdEntryOffset)) {
      setReason(Reason, "failed to update kernel descriptor entry for '" +
                            Twine(KD.KernelName) + "'");
      return false;
    }
  }
  return true;
}

bool applyTextDisplacement(const ElfView &Elf, const LLVMState &LS,
                           const DisplacementPlan &Plan,
                           WritableMemoryBuffer &OutBuf,
                           std::string *Reason) {
  const size_t InputSize = Elf.size();
  const size_t NewSize = Plan.newElfSize(InputSize);
  if (OutBuf.getBufferSize() != NewSize) {
    setReason(Reason, "output buffer has incorrect size for displacement");
    return false;
  }

  SmallVector<uint8_t> NewText = Plan.buildText(
      ArrayRef<uint8_t>(Elf.textData(), Elf.textSize()), LS.SNopBytes);
  if (NewText.size() != Plan.paddedTextSize()) {
    setReason(Reason, "rebuilt .text size does not match displacement plan");
    return false;
  }
  if (!repairBranches(Elf, LS, Plan, NewText, Reason))
    return false;

  std::unique_ptr<WritableMemoryBuffer> Tmp =
      WritableMemoryBuffer::getNewUninitMemBuffer(NewSize);
  if (!Tmp) {
    setReason(Reason, "failed to allocate temporary displacement buffer");
    return false;
  }

  uint8_t *Out = reinterpret_cast<uint8_t *>(Tmp->getBufferStart());
  const uint8_t *Input = Elf.data();
  const uint64_t TextOffset = Elf.textOffset();
  const uint64_t TextEnd = TextOffset + Elf.textSize();

  std::memcpy(Out, Input, TextOffset);
  std::memcpy(Out + TextOffset, NewText.data(), NewText.size());
  if (TextEnd < InputSize) {
    std::memcpy(Out + TextOffset + NewText.size(), Input + TextEnd,
                InputSize - TextEnd);
  }

  adjustSectionHeadersForTextGrowth(Out, NewSize, Elf, Plan.paddedGrowth());
  adjustProgramHeadersForTextGrowth(Out, NewSize, Elf, Plan.paddedGrowth());
  if (!adjustSymbolValuesForDisplacement(Out, NewSize, Elf, Plan, Reason))
    return false;

  if (!rewriteKernelDescriptorEntriesForDisplacement(*Tmp, Elf, Plan,
                                                     Reason))
    return false;

  std::memcpy(OutBuf.getBufferStart(), Tmp->getBufferStart(), NewSize);

  log() << "hotswap: displacement: grew ELF from " << InputSize << " to "
        << NewSize << " bytes (" << Plan.edits().size() << " edit"
        << (Plan.edits().size() == 1 ? "" : "s") << ", raw growth "
        << Plan.rawGrowth() << " bytes, padded growth "
        << Plan.paddedGrowth() << " bytes).\n";
  return true;
}

} // namespace

Expected<DisplacementPlan>
DisplacementPlan::create(const ElfView &Elf,
                         ArrayRef<DisplacementEdit> InputEdits) {
  if (InputEdits.empty())
    return makeDisplacementError("no displacement edits requested");

  std::vector<DisplacementEdit> Sorted;
  Sorted.reserve(InputEdits.size());
  for (const DisplacementEdit &Edit : InputEdits)
    Sorted.push_back(Edit);

  std::stable_sort(Sorted.begin(), Sorted.end(),
                   [](const DisplacementEdit &A, const DisplacementEdit &B) {
                     return A.Offset < B.Offset;
                   });

  uint64_t RawGrowth = 0;
  std::optional<uint64_t> PrevOffset;
  uint64_t PrevEnd = 0;
  for (const DisplacementEdit &Edit : Sorted) {
    if (Edit.ReplacementBytes.empty())
      return makeDisplacementError("displacement edit has empty replacement");
    if (Edit.Offset > Elf.textSize() ||
        Edit.OriginalSize > Elf.textSize() - Edit.Offset)
      return makeDisplacementError("displacement edit is out of .text bounds");
    if (Edit.ReplacementBytes.size() < Edit.OriginalSize)
      return makeDisplacementError("displacement edit shrinks code");
    if (Edit.ReplacementBytes.size() == Edit.OriginalSize)
      return makeDisplacementError("displacement edit has no size delta");
    if (PrevOffset && Edit.Offset < PrevEnd)
      return makeDisplacementError("displacement edits overlap");
    if (PrevOffset && Edit.Offset == *PrevOffset)
      return makeDisplacementError("multiple displacement edits share an offset");

    RawGrowth += Edit.ReplacementBytes.size() - Edit.OriginalSize;
    PrevOffset = Edit.Offset;
    PrevEnd = Edit.Offset + Edit.OriginalSize;
  }

  uint64_t PaddedGrowth = alignTo(RawGrowth, Align(maxPostTextAlignment(Elf)));
  return DisplacementPlan(Elf.textSize(), RawGrowth, PaddedGrowth,
                          std::move(Sorted));
}

bool DisplacementPlan::mapOffset(uint64_t OldOffset, DisplacementMapBias Bias,
                                 uint64_t &NewOffset) const {
  if (OldOffset > OldTextSize)
    return false;

  uint64_t Delta = 0;
  for (const DisplacementEdit &Edit : Edits) {
    const uint64_t EditEnd = Edit.Offset + Edit.OriginalSize;
    const uint64_t EditDelta =
        Edit.ReplacementBytes.size() - Edit.OriginalSize;

    if (OldOffset < Edit.Offset)
      break;

    if (OldOffset == Edit.Offset) {
      if (Edit.OriginalSize == 0 &&
          Bias == DisplacementMapBias::AfterInsertedBytes) {
        Delta += EditDelta;
        continue;
      }
      break;
    }

    if (OldOffset < EditEnd)
      return false;

    Delta += EditDelta;
  }

  NewOffset = OldOffset + Delta;
  return true;
}

bool DisplacementPlan::rangeOverlapsReplacement(uint64_t OldOffset,
                                                uint64_t Size) const {
  if (Size == 0)
    return false;
  const uint64_t OldEnd = OldOffset + Size;
  for (const DisplacementEdit &Edit : Edits) {
    if (Edit.OriginalSize == 0)
      continue;
    const uint64_t EditEnd = Edit.Offset + Edit.OriginalSize;
    if (OldOffset < EditEnd && OldEnd > Edit.Offset)
      return true;
  }
  return false;
}

SmallVector<uint8_t>
DisplacementPlan::buildText(ArrayRef<uint8_t> OldText,
                            ArrayRef<uint8_t> SNopBytes) const {
  SmallVector<uint8_t> Out;
  Out.reserve(paddedTextSize());

  uint64_t Pos = 0;
  for (const DisplacementEdit &Edit : Edits) {
    Out.append(OldText.begin() + Pos, OldText.begin() + Edit.Offset);
    Out.append(Edit.ReplacementBytes.begin(), Edit.ReplacementBytes.end());
    Pos = Edit.Offset + Edit.OriginalSize;
  }
  Out.append(OldText.begin() + Pos, OldText.end());

  uint64_t PadBytes = paddedTextSize() - Out.size();
  while (PadBytes >= MinInstSize && SNopBytes.size() == MinInstSize) {
    Out.append(SNopBytes.begin(), SNopBytes.end());
    PadBytes -= MinInstSize;
  }
  Out.append(PadBytes, uint8_t{0});
  return Out;
}

bool tryApplyTextDisplacement(const ElfView &Elf, const LLVMState &LS,
                              ArrayRef<DisplacementEdit> Edits,
                              WritableMemoryBuffer &Out,
                              std::string *Reason) {
  if (hasTextRelocations(Elf, Reason))
    return false;

  Expected<DisplacementPlan> PlanOrErr = DisplacementPlan::create(Elf, Edits);
  if (!PlanOrErr) {
    setReason(Reason, toString(PlanOrErr.takeError()));
    return false;
  }

  return applyTextDisplacement(Elf, LS, *PlanOrErr, Out, Reason);
}

std::unique_ptr<WritableMemoryBuffer>
tryApplyTextDisplacementToNewBuffer(const ElfView &Elf, const LLVMState &LS,
                                    ArrayRef<DisplacementEdit> Edits,
                                    std::string *Reason) {
  if (hasTextRelocations(Elf, Reason))
    return nullptr;

  Expected<DisplacementPlan> PlanOrErr = DisplacementPlan::create(Elf, Edits);
  if (!PlanOrErr) {
    setReason(Reason, toString(PlanOrErr.takeError()));
    return nullptr;
  }

  std::unique_ptr<WritableMemoryBuffer> Out =
      WritableMemoryBuffer::getNewUninitMemBuffer(
          PlanOrErr->newElfSize(Elf.size()));
  if (!Out) {
    setReason(Reason, "failed to allocate displacement output buffer");
    return nullptr;
  }
  if (!applyTextDisplacement(Elf, LS, *PlanOrErr, *Out, Reason))
    return nullptr;
  return Out;
}

} // namespace hotswap
} // namespace COMGR
