# GPT-OSS-120B on MI350 via gfx1250 → gfx950 HotSwap Transpilation

**Branch:** `transpiler-gfx1250-to-gfx942` (note: target is actually **gfx950**, not gfx942 — see §1.3)
**Base:** `rocm/amd-staging` @ `b1af74c44790`
**Author workspace:** `/home/harsh/llvm-project`
**Date:** 2026-04-24

---

## 1. Objective

Run the **GPT-OSS-120B** model, compiled for **gfx1250** (MI450/CDNA4 wave32 matrix), on an **MI350X** (**gfx950**/CDNA4 wave64) machine (`mi350-4`), by extending Comgr's HotSwap runtime to transpile gfx1250 code objects into gfx950 code objects at kernel load time, without changing the model or the compiler toolchain that produced the gfx1250 binaries.

### 1.1 Success Criteria

| # | Criterion | Measurement |
|---|-----------|-------------|
| S1 | `amd_comgr_hotswap_rewrite` accepts `source=gfx1250`, `target=gfx950` and returns a valid ELF | Unit test + `llvm-objdump -d --mcpu=gfx950` clean |
| S2 | A single transpiled GPT-OSS attention/MLP kernel runs correctly on `mi350-4` | Per-kernel diff vs reference (bit-exact or ULP-bounded) |
| S3 | End-to-end vLLM + AITER GPT-OSS-120B serving loop runs on `mi350-4` | Server starts, no dispatch-time failures |
| S4 | Model produces coherent output on a canonical prompt | Output tokens match a reference trace within tolerance |
| S5 | Throughput floor | Tokens/sec meets an agreed lower bound (TBD; track not block) |

### 1.2 Non-Goals

- Matching MI450 performance on MI350 — we expect a large perf gap from lane-redistribution overhead.
- Supporting arbitrary gfx1250 binaries — scope is bounded to the kernels GPT-OSS-120B actually dispatches under vLLM+AITER.
- Upstreaming to LLVM `main` — this is an AMD-staging effort; upstream comes later.

### 1.3 Branch Name Correction

The branch was created as `transpiler-gfx1250-to-gfx942` mirroring existing worktree conventions, but the target silicon is gfx950 (MI350X), **not** gfx942 (MI300X). Because gfx950 is largely a superset of gfx942 at the ISA level for the instructions we emit, most of the existing gfx942-targeted transpiler logic transfers directly. We will:

- Keep the branch name (rename later if noisy).
- Use `target_cpu = "gfx950"` throughout the code paths.
- Track any gfx942-specific code paths that need gfx950 equivalents in §4.2.

---

## 2. Current State (Inventory)

### 2.1 Committed code on `rocm/amd-staging`

The public API in `amd/comgr/src/comgr-hotswap.cpp` rejects any source/target whose processor is not `gfx1250`:

```28:29:amd/comgr/src/comgr-hotswap.cpp
  if (SourceIdent.Processor != "gfx1250" || TargetIdent.Processor != "gfx1250")
    return AMD_COMGR_STATUS_ERROR_INVALID_ARGUMENT;
```

Committed hotswap files target **B0 → A0** only:

- `comgr-hotswap.cpp` — public API bridge
- `comgr-hotswap-b0a0.cpp` — GFX1250 B0-to-A0 policy (production path)
- `comgr-hotswap-elf.cpp`, `comgr-hotswap-llvm.cpp`, `comgr-hotswap-internal.h` — infrastructure

Relevant in-flight comgr PRs (from the Confluence Tracker, not all merged):

| PR | Status | Role |
|----|--------|------|
| #2201 | merged | ELF parse/mutate, trampolines |
| #2202 | merged | MC decode/assemble, mnemonic swap |
| #2203 | merged | `retargetCodeObjectB0A0`, `amd_comgr_hotswap_rewrite` public API, weak stubs |
| #2222 | open draft | In-place patches (cluster load → global, `S_CLAUSE` → `S_NOP`) |
| #2212 | open | Trampoline patches (DS stride64, `TENSOR_LOAD_TO_LDS` + `S_PACK_HH`) |
| #2261 | open | `ApplyWmmaSplitPatches` |
| #2265 | open draft | `ApplyWmmaHazardPatch` |

### 2.2 Untracked work on disk (from prior sessions)

```
amd/comgr/src/comgr-hotswap-dwarf.cpp                 479 lines
amd/comgr/src/comgr-hotswap-liveness.cpp              343 lines
amd/comgr/src/comgr-hotswap-opcode-map.cpp             57 lines
amd/comgr/src/comgr-hotswap-opcodes.h                  (header)
amd/comgr/src/comgr-hotswap-transpiler.cpp           1924 lines   ← main pipeline
amd/comgr/src/comgr-hotswap-transpiler-handlers.cpp  1389 lines   ← per-instruction rewriters
amd/comgr/src/comgr-hotswap-transpiler-helpers.cpp    531 lines
amd/comgr/src/comgr-hotswap-transpiler-tables.cpp     287 lines
```

These files are **not yet committed anywhere** — they exist only as untracked content in the worktree. A parallel older snapshot lives on the checked-out branch `worktree-transpiler-gfx1250-to-gfx942` at `/home/harsh/llvm-project/.claude/worktrees/transpiler-gfx1250-to-gfx942/` (1939 commits behind origin/main, ~3 weeks stale). First task: rationalize these.

The transpiler already knows about gfx950 in several places (`comgr-hotswap-transpiler.cpp:114`, `:123`) but hardcodes gfx942-specific hazards / SGPR limits / packed-TID logic elsewhere (see §4.2).

### 2.3 Prior testing state (from `current_state.md`)

- **Source kernel:** a Tensile HH GEMM (`Cijk_Ailk_Bljk_HHS_..._MT16x16x32_MI16x16x1_..._WS32_WG16_2_1`) compiled for gfx1250.
- **Target:** gfx942 (MI300X via `sharkmi300x`), not gfx950.
- **Result:** 192/256 output cells correct, 64/256 zero in rows `{0, 2, 8, 10}`. Root cause suspected at the global-load offset computation in wave64 → current hypothesis is the `v58 >> 5` virtual-wave-ID formula is wrong after wave32→wave64 widening.
- **Last bug fixed:** `exec_hi = -1 → 0` in `WidenExecOperation` so lanes 32-63 don't produce garbage addresses.

### 2.4 Local review backlog (`findings.md`)

37 static-analysis findings against the committed B0→A0 code: 2 P0 (unencoded branches masked by `continue`; pre-encoding text mutation), 6 P1, 14 P2, 15 P3. The P0s are latent footguns in the shared infrastructure the transpiler reuses — worth landing fixes as part of this work.

### 2.5 Target machine `mi350-4`

Confirmed via SSH probe:

- 6× MI350X GPUs, `gfx950`, `sramecc:+ xnack:-`, Conductor-managed.
- Existing test harness `sharkmi300x` is **gfx942**; it is only useful for regression testing the old path, not for the real goal.

---

## 3. Architecture Delta (gfx1250 → gfx950)

From the Confluence pages (`gfx1250 to gfx942 : Architecture Differences & More`, `Transpiling gfx1250 to gfx942`) plus the MI400 Shader Programming Guide notes:

| Axis | gfx1250 (source) | gfx950 (target) | Translation |
|---|---|---|---|
| Encoding family | GFX12 | GFX9 | **Full re-encode, every instruction.** No binary compat. |
| Matrix instruction | `V_WMMA_*` (wave32) | `V_MFMA_*` (wave64) | Lane redistribution via `ds_bpermute_b32` + AGPR write/read (see §3.1) |
| Wave size for matrix | 32 | 64 | Widen EXEC and kernel descriptor, fix-up `tid`/`vcc` widths |
| Registers | 512 VGPRs, no AGPRs | 256 VGPRs + 256 AGPRs | MFMA result path must copy through AGPRs |
| FP8 MFMA | `V_WMMA_{F32,F16}_16X16X{64,128}_{FP8,BF8}_*` | Native `V_MFMA_F32_{16X16X128,32X32X64}_F8F6F4` (MI350 half the cycles of MI300) | Direct MFMA, no upcast |
| FP6/BF6 | Native WMMA scaled | No native — upcast to FP8/FP16 | Software emulation; target-specific cost |
| FP4 | `V_WMMA_SCALE16_F32_32X16X128_F4` (B0-only) | No native | Upcast via FP4→FP8 (requires block16 CVT emulation) |
| Wait counters | Split: `loadcnt`, `storecnt`, `kmcnt`, `dscnt`, `tensorcnt` | Combined: `vmcnt`, `lgkmcnt`, `expcnt` | Fold split counters into combined with conservative bounds |
| Barriers | Split / named / cluster barriers | `s_barrier` only | Decompose to single-barrier sequences |
| Scope/cache | `SCOPE_*` + `th:` hints | `glc`/`slc`/`dlc` bits | Table-driven field rewrite |
| LDS/memory | Unified 384KB WGP$ | 64KB CU-local + separate TCP | Kernel-descriptor limits must be clamped |
| VOP3PX2 / VOPD | Dual-issue clauses | No equivalent | Decompose into sequential VOP ops |
| TDM, cluster multicast loads | Present | Absent | Decompose into `global_load`/`buffer_load` |
| GDS, VINTRP, EXP, MTBUF | Removed | Present | Source never uses them — no action |

### 3.1 WMMA → MFMA lane redistribution (core complexity)

Confluence spells out the mapping used by the existing transpiler:

- **WMMA (wave32)**, for 16×16 output `D[row][col]`: `lane = (row < 8 ? 0 : 16) + col`, `GPR = row % 8`.
- **MFMA (wave64)**, same shape: `lane = col + 16 * (row / 4)`, `GPR = row % 4`.

Per-WMMA overhead on gfx950:

```
≈ 8 × ds_bpermute_b32  (input redistribute)
+ 4 × v_accvgpr_write_b32 (AGPR load)
+ 1 × V_MFMA_F32_16X16X16_F16
+ 4 × v_accvgpr_read_b32 (AGPR readback)
+ 4 × ds_bpermute_b32   (output redistribute)
≈ 20 instructions ≈ 400 cycles per matrix op  (ds_bpermute ~20 cyc on gfx9)
```

This is the dominant performance cost. The existing transpiler implements this path; the main risk for GPT-OSS is **scale-out correctness** across many different WMMA shapes, not the mechanism.

### 3.2 gfx942 vs gfx950 divergence (for the destination)

For our purposes these are mostly cosmetic — gfx950 is a CDNA4 extension of gfx942 with added F8F6F4 MFMA variants and throughput improvements. Known divergences relevant to the transpiler:

- Machine identifier / e_flags: `gfx950 = 0x4f`, `gfx942 = 0x4c` — already handled.
- MFMA K-dim expansion: gfx950 can do `16X16X64` (vs gfx942's `16X16X32`) for some dtypes — lets us emit fewer redistributions per WMMA if we pattern-match.
- TRANS→VALU hazard: gfx942 code path in `comgr-hotswap-transpiler.cpp:1460`; gfx950 hazard behavior needs verification.
- Packed TID (`v0 = X | (Y<<10)`) at `:1045` is declared gfx942-specific — verify gfx950 equivalent.
- `target_cpu.find("gfx942")` check in `comgr-hotswap-transpiler-handlers.cpp:849` explicitly excludes gfx950 — needs to be generalized.

---

## 4. Work Plan

### Phase 0 — Consolidate prior work (prereq, 1–2 days)

- **0.1** Commit the 8 untracked transpiler files onto this branch as a baseline "WIP transpiler (gfx942 target, known-buggy)" commit. No code changes — just get them tracked so subsequent diffs are readable.
- **0.2** Save `current_state.md` / `findings.md` into a `docs/hotswap/` subdir and delete them from the repo root, or exclude via `.gitignore` — they are internal notes, not shipping code.
- **0.3** Diff the committed files against the stale worktree at `.claude/worktrees/transpiler-gfx1250-to-gfx942/` to confirm the on-disk untracked set is the latest; record any salvage-worthy deltas.
- **0.4** Decide disposition of the P0/P1 findings in `findings.md`. Recommendation: land F1 (masked `EncodeSBranch` failure) and F6 (un-NOP'd tail) before building on the infrastructure.

**Deliverable:** clean `git log` starting point; all code in-tree; failing tests OK.

### Phase 1 — Wire gfx1250 → gfx950 into the public API (2–3 days)

- **1.1** Generalize `comgr-hotswap.cpp` to dispatch on `(source, target)`:
  - `(gfx1250, gfx1250)` → existing `retargetCodeObjectB0A0`
  - `(gfx1250, gfx950)` → new `retargetCodeObjectTranspile(..., "gfx950")`
  - anything else → `INVALID_ARGUMENT` (for now)
- **1.2** Add a `retargetCodeObjectTranspile` entry in `comgr-hotswap-internal.h` and implement it in `comgr-hotswap-transpiler.cpp` to call the existing pipeline with `RewriteConfig{.TargetCpu = "gfx950"}`.
- **1.3** Generalize every explicit `== "gfx942"` / `find("gfx942")` check in the transpiler to an ISA feature predicate (`isGfx9Target(cpu)` → true for 940/941/942/950/90a) unless the check is genuinely gfx942-specific.
- **1.4** Update `PatchElfMetadata` so `.wavefront_size`, `.max_flat_workgroup_size`, `e_flags`, `amdhsa.target`, ISA-note string all reflect gfx950 (`target_mach = 0x4f`).
- **1.5** Expose a CLI/test harness `hotswap-transpile` (or extend the existing `transpile_test` binary) that takes `input.co` and `--target gfx950` and writes `output.co`.

**Exit test:** `llvm-objdump -d --mcpu=gfx950 output.co` produces clean disassembly for the single Tensile HH kernel.

### Phase 2 — Reproduce and fix known correctness bug (3–5 days)

The existing `gfx942` run is 192/256 correct with zeros in rows `{0,2,8,10}`. Before scaling to GPT-OSS, we need a single-kernel passing baseline on gfx950.

- **2.1** Build comgr on mi350-4 (native, since the machine has gfx950 hardware). Output library is used by a local `transpile_test` and a kernarg-driving harness similar to `test_hh_fullkernarg`.
- **2.2** Transpile the Tensile HH kernel with `target=gfx950`, dispatch on `mi350-4`, capture the 16×16 output.
- **2.3** Diagnose the zero-row pattern:
  - Trace the `v8` (global load offset) computation in the transpiled wave64 output — decode the relevant `v_mul_lo_u32` chain and confirm the address matches what the wave32 source expected. Current hypothesis (from `current_state.md` §"Remaining Bug"): virtual-wave-ID formula `(v58 >> 5) & 1` collapses to 0 for all lanes under exec_hi=0, so the second half of A-matrix never makes it into LDS.
  - Instrument: emit a debug variant that writes `v[42:45]` (raw global-load result) to a scratch buffer before the `ds_write`, to separate global-load vs LDS-write fault domains.
  - If the bug is wave-ID–related, the fix is in the prologue-rewriting path that adjusts `v0..v3` for wave32→wave64 (not exec handling).
- **2.4** Fix and regression-test on mi350-4. Add a new comgr lit test under `test/hotswap/transpile/` or a gtest under `unittests/HotswapTest.cpp`.

**Exit test:** Tensile HH kernel produces 256/256 correct output on mi350-4.

### Phase 3 — Enumerate the GPT-OSS-120B kernel set (3–5 days)

Before per-kernel work can start in parallel, we need the canonical list. This phase is the fan-out point for Phase 4.

- **3.1** Build the GPT-OSS toolchain the Confluence page prescribes (`therock-dist-linux-gfx1250-7.12.0a20260226.tar.gz`, `therock-npi:pytorch-2.10.0-rocm7.12.0a20260226-nightly-…`, AITER + vLLM for gfx1250).
- **3.2** Download GPT-OSS-120B weights, trim to 2 layers per Confluence (edit `config.json` `layer_types` + `num_hidden_layers`). Run once against FFM / gfx1250 as a reference; instrument HSA to dump every loaded code object. Also capture a full-36-layer dispatch list so we don't miss rarely-hit kernels.
- **3.3** Deduplicate: group dumped `.co` files by `(source_isa, kernel_template_hash)` — many Tensile/AITER kernels differ only in shape constants and share a rewriter path. Emit a manifest `kernels.json` with one row per unique kernel: source path, SHA, kernel name, size, tags (attention / MLP / rms / rotary / sampler / misc), shape parameters, reference output hash when deterministic.
- **3.4** Pre-classify each manifest entry by instruction features (WMMA shape+dtype, presence of VOPD / VOP3PX2 / TDM / cluster-load / split-waitcnt / scaled-WMMA / FP4-FP6). This tells us which transpiler handlers each kernel exercises, i.e. which Confluence §2 categories we must have working for this kernel.

**Exit criterion:** `kernels.json` with ~N entries, where N is the unique-kernel count (expected O(50–200)) and each entry has a feature classification.

### Phase 4 — Per-kernel correctness (parallel, 2–3 weeks)

Per the updated strategy: each kernel is worked end-to-end independently — transpile correctness and on-device correctness in parallel tracks — before anything is composed into a whole-model run. Each kernel in `kernels.json` is its own ticket with four states:

| State | Meaning |
|---|---|
| T1 | Transpiler emits clean gfx950 ELF, disassembles without errors |
| T2 | Transpiled kernel runs on mi350-4 without faulting |
| T3 | Transpiled kernel produces numerically correct output |
| T4 | Kernel has a persisted lit/gtest regression test in-tree |

These are accumulated; T4 implies T1-T3. The two parallel tracks are:

- **Track A — Offline transpile & disassembly (no GPU needed):** runs on any workstation. Goal T1. Fast loop (seconds per kernel) so it can fan out widely and triage missing handlers early.
- **Track B — On-device correctness on mi350-4:** goals T2 and T3. Slower loop but parallelizable across the 6 MI350X GPUs. Each kernel needs a driver harness (allocate buffers, fill inputs, dispatch, diff result). For Tensile/AITER kernels, reuse the reference output captured in Phase 3.2 (run the unmodified gfx1250 kernel under FFM, or the native gfx950 kernel where AITER provides one, as the ground truth).

Dependencies between tracks:

```
Phase 3.3 (manifest) → [Track A feature-by-feature] ──┐
                                                       ├→ Track B per-kernel (mi350-4) → T2,T3,T4
                                                       │
                       [Phase 2 zero-row fix] ─────────┘
```

Burn-down of handler gaps surfaced by Track A (priority order from Confluence §2):

1. Split wait counters → combined
2. Barrier decomposition
3. Scope/cache bit translation
4. `VOP3PX2` / `VOPD` decomposition
5. FP8/BF8 WMMA → native gfx950 MFMA `F8F6F4` (gfx950 is 2× gfx942 cycle count here — tune)
6. FP6/BF6 → FP16 upcast fallback (only if present in manifest)
7. FP4 → FP8 upcast (only if present)
8. TDM / cluster load decomposition to `global_load` / `buffer_load`

Per-kernel exit is T4. Phase-level exit is **every entry in `kernels.json` at T4**, or an explicit decision to mark a kernel as out-of-scope with written justification.

**Exit criterion:** full manifest at T4 (or documented triage).

### Phase 5 — Runtime integration (3–5 days)

Now that every individual kernel is correct in isolation, wire hotswap into the live dispatch path.

Two options:

- **5a. Offline pre-pass (bring-up):** transpile every `.co` in the AITER/vLLM build output, replace, and load. Lower-risk; decouples correctness from runtime hooks.
- **5b. Comgr-hooked path (production target):** intercept in the runtime's code-object loader so every `amd-hsa-code-object` of `gfx1250` ISA is transpiled to gfx950 before HSA finalizes. Touchpoints: ROCR / HSA-runtime + the HIP module loader. Confirm ownership with @lamb-j (Comgr code owner per README).

Start with 5a, migrate to 5b once stable.

**Exit criterion:** vLLM server starts on mi350-4 with GPT-OSS-120B (2-layer trim) using only transpiled code objects, and returns a response.

### Phase 6 — Whole-model end-to-end validation (3–5 days)

Only after Phase 4 and 5 are green. Running the full model exercises inter-kernel issues (state carried across dispatches, KV cache layout, allocator behavior) that per-kernel tests cannot catch.

- **6.1** Full 36-layer GPT-OSS-120B with a canonical prompt set; compare token-level output against the Phase 3.2 reference.
- **6.2** Throughput measurement — tokens/sec, prefill vs decode breakdown, per-layer kernel time. Expect significant slowdown vs native; quantify.
- **6.3** Failure triage spreadsheet: per-kernel correctness/perf status.

**Exit criterion:** S3/S4 from §1.1 — coherent model output on the full model.

### Phase 7 — Stretch / perf (open-ended)

- Reduce `ds_bpermute_b32` pressure (batch redistributions across consecutive WMMAs).
- Hoist permutation tables into constant cache / ROdata instead of literals per kernel.
- Pattern-match WMMA sequences to gfx950 deeper-K MFMAs (1× MFMA covering 2× K of 1 WMMA) to cut redistribution overhead.
- Dead-NOP elimination around hazard windows.
- Track against S5 throughput target.

---

## 5. Risks & Open Questions

| # | Risk | Mitigation |
|---|------|------------|
| R1 | Public API (`amd_comgr_hotswap_rewrite`) has no flags in the committed signature, but prior session referenced `AMD_COMGR_HOTSWAP_FLAG_TRANSPILE (0x4)`. API evolution may be needed. | §1.1 — decide whether to add a flagged variant or dispatch on source/target; align with @lamb-j. |
| R2 | The zero-row bug may turn out to be a deep issue in wave32→wave64 lane-ID translation, not a localized fix. | Phase 2 instruments the global-load result directly; we can fall back to a more aggressive prologue rewrite if the localized hypothesis fails. |
| R3 | GPT-OSS kernels may hit instructions the current transpiler has no handler for (VOPD, cluster loads, TDM). | Phase 3.3 classifies each kernel; (b) bucket is the capacity planning signal. |
| R4 | `mi350-4` is a shared Conductor-managed host; build+test iteration is slower than local. | Build comgr locally (on the workstation), copy the `.so` to mi350-4; only run tests on the GPU. |
| R5 | The stale `worktree-transpiler-gfx1250-to-gfx942` branch (1939 commits behind main) may diverge semantically from the current untracked files. | Phase 0.3 diffs and records salvageable deltas. |
| R6 | AITER + vLLM pin specific ROCm builds; transpiled code objects must be compatible with the HSA runtime shipped in `therock-dist-linux-gfx1250-7.12.0a20260226`. | Phase 5a (offline replacement) sidesteps ABI coupling while bringing up; Phase 5b addresses this long-term. |
| R7 | Performance may be so low it's not a usable demo even with all correctness landed. | S5 is a tracked-not-blocked criterion; Phase 7 is the mitigation. |
| R8 | Per-kernel correctness (Phase 4) can pass while whole-model (Phase 6) still fails — state carried across dispatches, allocator effects, KV-cache layout assumptions. | Phase 6 has its own triage; per-kernel tests don't discharge the whole-model obligation. |
| R9 | Manifest size (Phase 3.3) may be much larger than O(50–200) if AITER tiles produce many unique code objects. | Dedupe on kernel-template hash not file hash; treat shape variants as one rewriter path. |

### Open questions to resolve early

- **Q1.** Is there a gfx950-native reference run of GPT-OSS-120B we can diff against, or is FFM-on-gfx1250 the only reference?
- **Q2.** Does `mi350-4` have the 512GB VRAM partition the Confluence page describes, or is this specific to the FFM emulation path? (120B in FP8 is ~120GB → fits, but KV-cache for long contexts needs room.)
- **Q3.** Can we reuse the committed B0→A0 `ApplyWmmaSplitPatches` (PR #2261) for the WMMA-shape decomposition, or does cross-ISA need a separate split?
- **Q4.** Do we need a scale-factor-aware MFMA path on gfx950, or does GPT-OSS-120B use only standard FP8/FP16 WMMA (no scaled variants)?

---

## 6. References

### 6.1 In-tree sources

- `amd/comgr/src/comgr-hotswap-*.cpp` — in-tree hotswap infrastructure
- `amd/comgr/src/comgr-hotswap-transpiler*.cpp` — prior untracked transpiler work
- `current_state.md` — prior session findings (zero-row bug analysis)
- `findings.md` — 37-finding static review against B0→A0 infra

### 6.2 Hardware design documentation (authoritative)

- **gfx950 / MI3xx** — `~/gfxip/gfx9/doc/`
  - `arch/` — GFX9 architecture docs (incl. harvesting specs, `arch/mi350/`)
  - `mi350/` — MI350-specific: `Features/`, `HLD/`, `Performance/`, `Power_Analysis/`, `Verification/`, `design/`
  - `mi200/` — MI200 reference (for comparison)
  - `blockdv/`, `dv/`, `gcdv/`, `Gibraltar/`, `deployment/`, `proj/`, `test/`
- **gfx1250 / MI400/MI450** — `~/gfxip/mi400/doc/architecture/`
  - `features/`, `subsystem/`, `system/`, `ppa/`, `pmo_audit/`, `preFCRreview/`

These are the canonical sources for any target-specific behavior question the Confluence pages don't cover (encoding bits, hazard cycle counts, scheduling windows, cache geometry, MFMA rate tables).

### 6.3 Confluence pages

- `HotSwap: Design & Brainstorming Hub` (1620425029)
  - `gfx1250 to gfx942 : Architecture Differences & More` (1633927296)
  - `Transpiling gfx1250 to gfx942` (1634111335)
  - `Transpiling B0 to A0` (1633927250)
  - `B0 -> A0 Tracker` (1633275826)
- `GPT-OSS 120B Validation on MI450 through FFM Modeling Environment` (1587556666)

### 6.4 Git remotes / branches

- `rocm/amd-staging` — base branch for this work
- `harsh-nod/llvm-project` branch `amd-staging` — prior WIP fork
- `worktree-transpiler-gfx1250-to-gfx942` — stale prior worktree (1939 commits behind `origin/main`)

### 6.5 Hardware

- `mi350-4` — MI350X (gfx950), 6 GPUs, sramecc+ xnack- (target for all correctness testing)
- `sharkmi300x` — MI300X (gfx942) — legacy reference only; not the final target

---

## Appendix A — Confluence page index fetched this session

| ID | Title | Length (chars) |
|---|---|---|
| 1587556666 | GPT-OSS 120B Validation on MI450 through FFM | 34,855 (body) |
| 1620425029 | HotSwap: Design & Brainstorming Hub | 2,040 |
| 1633275826 | B0 -> A0 Tracker | 37,174 |
| 1633927250 | Transpiling B0 to A0 | 21,100 |
| 1633927296 | gfx1250 to gfx942 : Architecture Differences & More | 16,684 |
| 1634111335 | Transpiling gfx1250 to gfx942 | 67,659 |
| 1634160742 | rocprof-hotswap | 0 (empty) |
