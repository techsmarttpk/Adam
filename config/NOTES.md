# Sandbox snapshot lineage — canonical baseline &amp; known-unresolved tree structure

Date documented: 2026-08-11 (verified through 04 boots of `disk-resized-36gb-c-drive`, incl. 2 explicit `VBoxManage snapshot restore` cycles).

## Canonical golden baseline going forward: `disk-resized-36gb-c-drive`

This is the snapshot `config/development.toml` → `[sandbox].snapshot_name` now points to.

Its verification is *stronger* than the original `golden-v2-http-agent-verified` ever received:

| Boot | Operation | T0→bind | Evidence |
|------|-----------|---------|----------|
| 3–4 | plain `startvm` (persisted disk) | 3m00s / 2m16s | task 2026-08-11, `C:\tmp\boot4_*`, agent-log bind lines |
| 5–6 | **explicit `VBoxManage snapshot restore`** (the real per-run op) | ≈1m58s / ≈2m00s | task 2026-08-11 §7, `C:\tmp\restore{1,2}_*.log`, trace/phases |

Per the 2026-08-11 investigation, the 8m01s/8m31s of boots 1–2 was a **one-time post-resize transient** (first boots after the 20→36 GB diskpart extend), not the per-run restore cost; snapshot restore does not discard anything that re-introduces it (Add-Type compile stayed ~15.5 s on both restores).

`disk-resized-36gb-c-drive` also carries the `C:\ADAM\samples` staging directory (confirmed present on-guest via `guestcontrol` 2026-08-11, created 2026-08-09 13:05:46, still empty as designed) — inherited from `clean-samples-dir`.

## Known-unresolved lineage fact (do NOT assume otherwise)

```
clean (4a81ac05-7cbb-4275-8ecf-57cd1e0b63f6)
├── golden-v2-http-agent-verified (4f293bee-…)            ← original golden, still intact, untouched
├── clean-samples-dir (4a15ae25-…)                          ← sibling of golden, NOT its child
│   └── disk-resized-36gb-c-drive (93ec1364-…)  ← current baseline; descends from the samples branch
└── clean (hardened, af1bc3a4-…)
```

`golden-v2-http-agent-verified` and the `clean-samples-dir → disk-resized-36gb-c-drive` branch are **siblings under `clean`** — they are *not* in a parent/child relationship. Anything that later restructures the snapshot tree (e.g. collapsing to a single linear chain for ADAM's `restore_snapshot` atomicity assumptions in `adam/sandbox/controller.py`) must treat these as two distinct branches and reconcile them explicitly; do not assume `disk-resized-36gb-c-drive` is a descendant of `golden-v2-http-agent-verified`.

`golden-v2-http-agent-verified` is left **intact** (and `clean-samples-dir` likewise) as a rollback target. `disk-resized-36gb-c-drive` is the new working baseline purely because it is (a) the only snapshot verified through the actual per-run restore path, and (b) its larger disk is the current production need.
