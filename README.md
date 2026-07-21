# ADAM — Policy Engine + Adaptive Deception (Dev C)

Standalone implementation of the Policy Engine (`adam/policy/`) and Adaptive Deception (`adam/deception/`) modules.

## Scope
- `adam/policy/` — Rule loader, compiler, engine, and predicates.
- `adam/deception/` — Deception primitive registry, engine, and primitives.

## Running Tests
```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

