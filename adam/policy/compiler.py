"""
Compiler — turns the raw dicts RuleLoader hands back into CompiledRule
objects with a ready-to-call condition function. Keeping compile() separate
from load() means loader.py stays pure "read YAML off disk" and compiler.py
stays pure "dict -> evaluable form," each independently testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adam.policy.conditions import ConditionFn, compile_when


@dataclass(frozen=True)
class RuleBudget:
    max_per_session: int = 1
    cooldown_seconds: float = 0.0


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    version: str
    condition: ConditionFn
    action: str
    priority: int
    parameters: dict[str, Any]
    budget: RuleBudget


def compile_rule(raw_rule: dict[str, Any]) -> CompiledRule:
    then_block = raw_rule["then"]
    budget_block = raw_rule.get("budget", {}) or {}

    return CompiledRule(
        rule_id=raw_rule["id"],
        version=str(raw_rule.get("version", "1.0.0")),
        condition=compile_when(raw_rule["when"]),
        action=then_block["action"],
        priority=int(then_block.get("priority", 0)),
        parameters=then_block.get("parameters", {}) or {},
        budget=RuleBudget(
            max_per_session=int(budget_block.get("max_per_session", 1)),
            cooldown_seconds=float(budget_block.get("cooldown_seconds", 0.0)),
        ),
    )


def compile_ruleset(raw_rules: list[dict[str, Any]]) -> list[CompiledRule]:
    # Highest priority evaluated first — matters when two rules both match
    # the same SemanticEvent and budgets/cooldowns make ordering visible.
    compiled = [compile_rule(r) for r in raw_rules]
    return sorted(compiled, key=lambda r: r.priority, reverse=True)
