# HotSwap

HotSwap rewrites AMDGPU code objects at load time so that a binary built for one
gfx1250 stepping runs correctly on another. The `amd_comgr_hotswap_rewrite` API
applies a small set of stepping-specific patches in place, without recompiling
the code object.

This directory ships two COMGR-side pieces:

- The `amd_comgr_hotswap_rewrite` API, which applies stepping-specific patches
  and optional entry trampolines to a single code object.
- The transpiler, a raiser-based path for the heavier cross-ISA case. It is
  documented at the bottom of this file.

COMGR does not ship an `HSA_TOOLS_LIB` runtime tool. Runtime interception is
owned by rocm-systems' `libhsa-hotswap.so`, which loads code objects through HSA
and calls `amd_comgr_hotswap_rewrite` when its policy allows a rewrite.

## Running at runtime

Build and install the hotswap tool from rocm-systems, then point
`HSA_TOOLS_LIB` at that library and run any HIP or HSA application unchanged:

```bash
HSA_TOOLS_LIB=/opt/rocm/lib/libhsa-hotswap.so ./my_app
```

`HSA_TOOLS_LIB` tells `libhsa-runtime` what tool to hand each code object to
before dispatch. The rocm-systems tool rewrites gfx1250 A0 loads for the
B0-to-A0 stepping patches. If `AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES=1` is set,
the tool also asks COMGR to redirect gfx1250 kernel descriptor entries through
entry stubs, independent of the detected A0/B0 revision. Everything else passes
through unchanged.

If a rewrite fails, the runtime tool logs the failure and forwards the original
code object. The application still runs, just without the rewrite applied.

## Supported architectures

| Architecture        | Status      |
| ------------------- | ----------- |
| gfx1250, ASIC rev A0 | Rewrite armed |
| gfx950              | Coming soon |
| gfx942              | Coming soon |

HotSwap currently requires a homogeneous GPU setup. Running it across multiple
GPUs is not supported.

## Environment variables

| Variable                   | Effect                                                        |
| -------------------------- | ------------------------------------------------------------- |
| `HSA_TOOLS_LIB`                         | Standard HSA hook. Set it to rocm-systems' `libhsa-hotswap.so` to load the runtime tool. |
| `AMD_COMGR_HOTSWAP_ENTRY_TRAMPOLINES`   | Set to `1` to redirect gfx1250 kernel descriptor entries through COMGR-generated entry stubs, independent of A0/B0 stepping. Off by default. |
| `HSA_HOTSWAP_TOOL_VERBOSE`              | rocm-systems runtime-tool diagnostic logging, when supported by that tool. |

## Transpiler (cross-gen)

The transpiler is the heavier sibling to the byte-level rewrite. It raises
AMDGPU code objects into LLVM IR, re-lowers them through the stock AMDGPU backend
for a different target ISA, and relinks the result into a single merged HSACO.
The rewrite path applies in-place stepping patches; the transpiler instead hands
the whole code object to the IR pipeline. It can be built standalone for
development:

```bash
cmake -S amd/comgr/hotswap -B build-hotswap \
  -DLLVM_DIR=$PWD/build/lib/cmake/llvm
ninja -C build-hotswap
ctest --test-dir build-hotswap -L transpiler
```
