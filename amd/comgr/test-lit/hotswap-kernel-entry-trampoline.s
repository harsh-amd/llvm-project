// COM: HotSwap redirects kernel descriptors to appended PC-relative entry
// COM: stubs only when the entry-trampoline flag is enabled.

// RUN: %clang -target amdgcn-amd-amdhsa -mcpu=gfx1250 -nostdlib %s -o %t.elf

// RUN: hotswap-rewrite %t.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250 amdgcn-amd-amdhsa--gfx1250 \
// RUN:   | %FileCheck --check-prefix=DEFAULT %s
// DEFAULT: RESULT: SUCCESS

// RUN: AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1 hotswap-rewrite %t.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250 amdgcn-amd-amdhsa--gfx1250 \
// RUN:   --output %t.out.elf \
// RUN:   | %FileCheck --check-prefix=API %s
// API: RESULT: SUCCESS

// RUN: %llvm-objdump -d %t.out.elf | %FileCheck --check-prefix=DISASM %s

// RUN: AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1 hotswap-rewrite %t.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific+ \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific+ \
// RUN:   --output %t.b0b0.elf \
// RUN:   | %FileCheck --check-prefix=API %s
// RUN: %llvm-objdump -d %t.b0b0.elf | %FileCheck --check-prefix=DISASM %s

// RUN: AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1 hotswap-rewrite %t.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific- \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific- \
// RUN:   --output %t.a0a0.elf \
// RUN:   | %FileCheck --check-prefix=API %s
// RUN: %llvm-objdump -d %t.a0a0.elf | %FileCheck --check-prefix=DISASM %s

// RUN: AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1 hotswap-rewrite %t.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific+ \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific- \
// RUN:   --output %t.b0a0.elf \
// RUN:   | %FileCheck --check-prefix=API %s
// RUN: %llvm-objdump -d %t.b0a0.elf | %FileCheck --check-prefix=DISASM %s

// RUN: AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1 hotswap-rewrite %t.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific- \
// RUN:   amdgcn-amd-amdhsa--gfx1250:gfx1250-b0-specific+ \
// RUN:   --output %t.a0b0.elf \
// RUN:   | %FileCheck --check-prefix=API %s
// RUN: %llvm-objdump -d %t.a0b0.elf | %FileCheck --check-prefix=DISASM %s

// DISASM-LABEL: <entry_tramp_kernel>:
// DISASM: s_endpgm
// DISASM: global_wb
// DISASM-NEXT: v_nop
// DISASM-NEXT: s_get_pc_i64 s[100:101]
// DISASM-NEXT: s_add_co_u32 s100
// DISASM-NEXT: s_add_co_ci_u32 s101
// DISASM-NEXT: s_set_pc_i64 s[100:101]

// RUN: AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1 hotswap-rewrite %t.out.elf \
// RUN:   amdgcn-amd-amdhsa--gfx1250 amdgcn-amd-amdhsa--gfx1250 \
// RUN:   --output %t.out2.elf \
// RUN:   | %FileCheck --check-prefix=API2 %s
// API2: RESULT: SUCCESS
// RUN: cmp %t.out.elf %t.out2.elf

.amdgcn_target "amdgcn-amd-amdhsa--gfx1250"
.text
.globl entry_tramp_kernel
.p2align 8
.type entry_tramp_kernel,@function
entry_tramp_kernel:
  v_mov_b32_e32 v0, 0
  s_endpgm
.Lentry_tramp_kernel_end:
.size entry_tramp_kernel, .Lentry_tramp_kernel_end-entry_tramp_kernel

.rodata
.p2align 8
.amdhsa_kernel entry_tramp_kernel
  .amdhsa_next_free_vgpr 1
  .amdhsa_next_free_sgpr 1
.end_amdhsa_kernel
