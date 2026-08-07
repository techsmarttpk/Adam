"""
Catalogue — decorator-based registry mapping a PolicyDecision.action name
(e.g. "SPAWN_FAKE_DC_ARTIFACTS") to a DeceptionPrimitive class.

Same pattern as adam/policy/predicates/: adding a primitive means adding a
file with a decorator, never editing a central list (§10.3 — this is
exactly where four-way merge conflicts would otherwise happen).
"""

from __future__ import annotations

from typing import Callable, Type

from adam.deception.primitives.base import DeceptionPrimitive

_CATALOGUE: dict[str, Type[DeceptionPrimitive]] = {}


def register_primitive(action_name: str) -> Callable[[Type[DeceptionPrimitive]], Type[DeceptionPrimitive]]:
    def decorator(cls: Type[DeceptionPrimitive]) -> Type[DeceptionPrimitive]:
        if action_name in _CATALOGUE:
            raise ValueError(f"Action '{action_name}' already has a registered primitive")
        _CATALOGUE[action_name] = cls
        return cls

    return decorator


def get_primitive_class(action_name: str) -> Type[DeceptionPrimitive]:
    try:
        return _CATALOGUE[action_name]
    except KeyError as exc:
        raise KeyError(
            f"No deception primitive registered for action '{action_name}'. "
            f"Known actions: {sorted(_CATALOGUE)}"
        ) from exc


import importlib
import pkgutil
import adam.deception.primitives

def _load_all_primitives() -> None:
    package = adam.deception.primitives
    prefix = package.__name__ + "."
    for _, module_name, _ in pkgutil.iter_modules(package.__path__, prefix):
        importlib.import_module(module_name)

_load_all_primitives()
