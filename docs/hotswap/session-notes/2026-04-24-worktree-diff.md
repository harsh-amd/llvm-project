# Worktree Diff Summary: Main vs `.claude/worktrees/transpiler-gfx1250-to-gfx942/`

Date: 2026-04-24

## File-by-file comparison

| File | Diff lines | Verdict |
|------|-----------|---------|
| `comgr-hotswap-transpiler.cpp` | 57 | Stale — annotation-only (`HSA_HOTSWAP_ANNOTATE`) |
| `comgr-hotswap-transpiler-handlers.cpp` | 172 | **Salvage-worthy** — improved WMMA lane redistribution |
| `comgr-hotswap-transpiler-helpers.cpp` | 47 | Stale — annotation propagation |
| `comgr-hotswap-transpiler-tables.cpp` | 3 | Stale — trivial whitespace |
| `comgr-hotswap-dwarf.cpp` | 0 | Identical |
| `comgr-hotswap-liveness.cpp` | 0 | Identical |
| `comgr-hotswap-opcode-map.cpp` | 0 | Identical |
| `comgr-hotswap-opcodes.h` | 0 | Identical |

## Hunk analysis

### `comgr-hotswap-transpiler.cpp` (57 diff lines)
- **All hunks: STALE.** Worktree adds `HSA_HOTSWAP_ANNOTATE` env-var-gated source
  annotation comments ("; src: <original instruction>") to translated assembly.
  This is a debug aid, not a correctness fix. The main tree copy is cleaner without it.

### `comgr-hotswap-transpiler-handlers.cpp` (172 diff lines)
- **SALVAGE-WORTHY:** Worktree has rewritten WMMA lane redistribution with detailed
  comments explaining the w32->w64 register mapping for both D/acc gather and srcA/B
  gather paths. The mapping documentation (RDNA4 WMMA D/acc layout, CDNA3 MFMA
  D/acc layout, K-group interleaving) is valuable. The actual gather implementation
  uses a parity-grouped approach with buffer VGPRs (v100, v101) that differs from
  the main tree's simpler `emitRedistribute` lambda.
- **Decision:** The main tree's simpler implementation may be easier to debug during
  Phase 2. The worktree's detailed comments should be ported as documentation.
  The rewritten gather logic should be evaluated after the zero-row bug is fixed.

### `comgr-hotswap-transpiler-helpers.cpp` (47 diff lines)
- **STALE.** Annotation comment propagation only -- same `HSA_HOTSWAP_ANNOTATE` pattern.

### `comgr-hotswap-transpiler-tables.cpp` (3 diff lines)
- **STALE.** Trivial diff, no meaningful changes.

## Conclusion

Use the **main tree** copies as the WIP baseline (Step 0.4). The worktree's WMMA
lane redistribution comments are worth porting later (Step 2.4) but the code
changes should be evaluated after the zero-row bug root cause is confirmed.
