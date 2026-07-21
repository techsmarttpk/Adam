# ADAM — Policy Engine + Adaptive Deception (Dev C scaffold)

Scope: `adam/policy/`, `adam/deception/`, `rules/`, per ARCHITECTURE.md §5.5,
§5.6 and the team role split. Everything here runs standalone — no VM, no
event bus, no other dev's module required — via the fixture-based tests.

## What's real vs. stubbed

- `adam/policy/` and `adam/deception/` are working code, not placeholders:
  loader → compiler → engine, and catalogue → primitive → engine both run
  and are tested end to end (`tests/unit/`).
- `adam/contracts/` here is a **local stub** mirroring ARCHITECTURE.md §7
  field-for-field, so this module is testable before the real, team-reviewed
  `adam/contracts/` package exists. Once that lands (all four devs sign off,
  §4.1 P1), delete this local copy and import the real one — don't merge
  this stub into `main` as-is.
- The bus wiring (subscribing to `SemanticEvent`, publishing `MutationResult`
  back per ADR-003) and the real `ISandboxController` are intentionally
  **not** implemented here — that's Dev A's (Pranav's) module and the
  composition root (`adam/api/deps.py`). `GuestMutationChannel` in
  `primitives/base.py` is the Protocol your code needs from his; swap the
  `FakeGuestChannel` in tests for his real controller when it exists.

## Run it

```bash
pip install -r requirements.txt --break-system-packages   # or a venv
PYTHONPATH=. pytest tests/ -v
```

## Where to add things next

- New intent → new rule in `rules/default/*.yaml` (validate against
  `rules/schema/rule.schema.json`).
- New DSL condition your rules need → `adam/policy/conditions.py`.
- Condition the DSL can't express → a new function in
  `adam/policy/predicates/builtin.py` with `@predicate("name")`.
- New deception response → a new file in `adam/deception/primitives/` with
  `@register_primitive("ACTION_NAME")`, implementing `_build_changes()` and
  `_plausibility()`. One file, no central list to edit.

## Sanity-checked against ARCHITECTURE.md

- Policy is a pure function of (event, context) — no I/O in `evaluate()` (ADR-004).
- Suppressed decisions are emitted, not dropped (§7.4) — see
  `test_low_confidence_is_suppressed_not_dropped`.
- Every primitive scores plausibility (§2.4) and is revert-capable in shape
  (base class has `revert()` — fill in a concrete `revert_async` per primitive
  as you build them out).
- `DeceptionEngine.execute_async` never calls VBoxManage directly — only the
  injected `GuestMutationChannel`.
