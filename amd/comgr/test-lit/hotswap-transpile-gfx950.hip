// COM: End-to-end coverage of the HotSwap transpile pipeline for
// COM: gfx1250 -> gfx950 cross-family rewriting.

// COM: Compile a tiny kernel targeting gfx1250 to a raw code object.
// RUN: %clang --offload-arch=gfx1250 --offload-device-only \
// RUN:     --no-gpu-bundle-output -nogpulib -nogpuinc \
// RUN:     %s -o %t.input.elf

// COM: Sanity: input is a gfx1250 ELF.
// RUN: %llvm-readelf -h %t.input.elf | %FileCheck --check-prefix=INPUT-FLAGS %s
// INPUT-FLAGS: Flags:{{.*}}gfx1250

// COM: Run hotswap-kernel-test to transpile gfx1250 -> gfx950.
// RUN: hotswap-kernel-test %t.input.elf --target gfx950 \
// RUN:     --dump-out %t.output.elf \
// RUN:   | %FileCheck --check-prefix=STATUS %s
// STATUS: TRANSPILE: SUCCESS
// STATUS: RESULT: PASS

// COM: Output ELF identifies as gfx950.
// RUN: %llvm-readelf -h %t.output.elf | %FileCheck --check-prefix=OUTPUT-FLAGS %s
// OUTPUT-FLAGS: Flags:{{.*}}gfx950

// COM: No residual gfx1250 strings in the output metadata.
// RUN: %llvm-readelf --notes %t.output.elf | %FileCheck --check-prefix=OUTPUT-META %s
// OUTPUT-META: amdhsa.target: amdgcn-amd-amdhsa--gfx950
// OUTPUT-META-NOT: gfx1250

// COM: .text section is present and disassemblable as gfx950 code.
// RUN: %llvm-readelf --section-headers %t.output.elf \
// RUN:   | %FileCheck --check-prefix=SECTIONS %s
// SECTIONS: .text{{.*}}PROGBITS

// RUN: %llvm-objdump -d --mcpu=gfx950 %t.output.elf \
// RUN:   | %FileCheck --check-prefix=DISASM %s
// DISASM: file format elf64-amdgpu
// DISASM: Disassembly of section .text:
// DISASM: s_endpgm

__attribute__((global))
void add(float *A, float *B, float *C) {
  *C = *A + *B;
}
