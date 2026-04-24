# HotSwap Transpiler: gfx1250 to gfx950

This project implements a HotSwap binary transpiler that converts GPU kernels
compiled for gfx1250 (MI350X) into gfx950 (MI300X) machine code at load time.
The goal is to enable running GPT-OSS-120B on MI350X hardware by transparently
rewriting code objects through AMD COMGR.

## Directory layout

- `gfx1250-to-gfx950-plan.md` -- Original transpilation plan (kept for reference).
- `session-notes/` -- Chronological working notes from development sessions.
