//===- hotswap-kernel-test.c - Per-kernel HotSwap transpile + dispatch ----===//
//
// Part of Comgr, under the Apache License v2.0 with LLVM Exceptions. See
// amd/comgr/LICENSE.TXT in this repository for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// CLI harness for per-kernel HotSwap transpile testing.
//
// Usage:
//   hotswap-kernel-test <input.co> --target <gfx950|gfx942>
//       [--dump-out <path>]
//       [--source-isa <isa>]
//
// The tool:
//   1. Reads the input code object (ELF).
//   2. Calls amd_comgr_hotswap_rewrite to transpile from source to target ISA.
//   3. Optionally dumps the transpiled output to --dump-out.
//   4. Reports success/failure and basic statistics.
//
// Device dispatch (HSA load + kernarg + launch + compare) is planned for a
// follow-up once the HSA runtime is available in the test environment.
//
//===----------------------------------------------------------------------===//

#include "amd_comgr.h"
#include "common.h"

static void usage(const char *prog) {
  printf("usage: %s <input.co> --target <gfx950|gfx942|gfx90a>\n"
         "       [--dump-out <path>] [--source-isa <isa>]\n",
         prog);
}

int main(int argc, char *argv[]) {
  const char *InputFile = NULL;
  const char *TargetCPU = NULL;
  const char *DumpOutPath = NULL;
  const char *SourceISA = "amdgcn-amd-amdhsa--gfx1250";

  // Parse CLI arguments
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    }
    if (argv[i][0] != '-' && !InputFile) {
      InputFile = argv[i];
      continue;
    }
    if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
      TargetCPU = argv[++i];
    } else if (strcmp(argv[i], "--dump-out") == 0 && i + 1 < argc) {
      DumpOutPath = argv[++i];
    } else if (strcmp(argv[i], "--source-isa") == 0 && i + 1 < argc) {
      SourceISA = argv[++i];
    } else {
      printf("unknown argument: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
  }

  if (!InputFile) {
    printf("ERROR: input file is required\n");
    usage(argv[0]);
    return 1;
  }

  if (!TargetCPU) {
    printf("ERROR: --target is required\n");
    usage(argv[0]);
    return 1;
  }

  // Build full ISA string for target
  char TargetISA[128];
  snprintf(TargetISA, sizeof(TargetISA), "amdgcn-amd-amdhsa--%s", TargetCPU);

  // Read input ELF
  char *ElfBuf = NULL;
  size_t ElfSize = (size_t)setBuf(InputFile, &ElfBuf);

  printf("INPUT: %s (%zu bytes)\n", InputFile, ElfSize);
  printf("SOURCE: %s\n", SourceISA);
  printf("TARGET: %s\n", TargetISA);

  // Create comgr data object for input
  amd_comgr_data_t InputData;
  amd_comgr_(create_data(AMD_COMGR_DATA_KIND_EXECUTABLE, &InputData));
  amd_comgr_(set_data(InputData, ElfSize, ElfBuf));

  // Transpile
  amd_comgr_data_t OutputData;
  amd_comgr_status_t Status =
      amd_comgr_hotswap_rewrite(InputData, SourceISA, TargetISA, &OutputData);

  if (Status != AMD_COMGR_STATUS_SUCCESS) {
    const char *StatusStr = "unknown";
    amd_comgr_status_string(Status, &StatusStr);
    printf("TRANSPILE: FAILED (%s)\n", StatusStr);
    amd_comgr_(release_data(InputData));
    free(ElfBuf);
    return 2;
  }

  // Get output size
  size_t OutSize = 0;
  amd_comgr_(get_data(OutputData, &OutSize, NULL));

  printf("TRANSPILE: SUCCESS (%zu bytes output)\n", OutSize);

  // Dump output if requested
  if (DumpOutPath) {
    dumpData(OutputData, DumpOutPath);
    printf("DUMPED: %s\n", DumpOutPath);
  }

  // Cleanup
  amd_comgr_(release_data(OutputData));
  amd_comgr_(release_data(InputData));
  free(ElfBuf);

  printf("RESULT: PASS\n");
  return 0;
}
