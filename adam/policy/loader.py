"""
RuleLoader — reads every *.yaml file under a ruleset directory and returns
raw rule dicts. Validation errors here must fail fast at startup
(§14.2: "Rule file invalid → Refuse to start"), never surface mid-session.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from adam.contracts.interfaces import IRuleLoader


class RuleSyntaxError(Exception):
    """Raised when a rule file is malformed or missing required fields."""


_REQUIRED_TOP_LEVEL = {"id", "when", "then"}
_REQUIRED_THEN = {"action", "priority"}


class RuleLoader(IRuleLoader):
    def load(self, ruleset_path: str) -> list[dict[str, Any]]:
        base = Path(ruleset_path)
        if not base.exists():
            raise RuleSyntaxError(f"Ruleset path does not exist: {ruleset_path}")

        rules: list[dict[str, Any]] = []
        for yaml_file in sorted(base.glob("*.yaml")):
            with yaml_file.open("r", encoding="utf-8") as fh:
                documents = yaml.safe_load(fh) or []
            if not isinstance(documents, list):
                raise RuleSyntaxError(
                    f"{yaml_file}: expected a top-level list of rules, got {type(documents).__name__}"
                )
            for raw_rule in documents:
                self._validate(raw_rule, source=yaml_file.name)
                rules.append(raw_rule)

        self._check_duplicate_ids(rules)
        return rules

    @staticmethod
    def _validate(raw_rule: dict[str, Any], *, source: str) -> None:
        missing = _REQUIRED_TOP_LEVEL - raw_rule.keys()
        if missing:
            raise RuleSyntaxError(f"{source}: rule missing required field(s): {missing}")

        then_block = raw_rule.get("then", {})
        missing_then = _REQUIRED_THEN - then_block.keys()
        if missing_then:
            raise RuleSyntaxError(
                f"{source}: rule '{raw_rule.get('id')}' 'then' block missing: {missing_then}"
            )

    @staticmethod
    def _check_duplicate_ids(rules: list[dict[str, Any]]) -> None:
        seen: set[str] = set()
        for rule in rules:
            rule_id = rule["id"]
            if rule_id in seen:
                raise RuleSyntaxError(f"Duplicate rule id across ruleset: {rule_id}")
            seen.add(rule_id)
