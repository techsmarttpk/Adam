import os
import yaml
import logging
from typing import List, Dict, Any, Optional
from adam.common.errors import RuleSyntaxError

logger = logging.getLogger("adam.policy.loader")

class PolicyRule:
    def __init__(self, rule_dict: Dict[str, Any]) -> None:
        self.rule_id = rule_dict.get("id")
        if not self.rule_id:
            raise RuleSyntaxError("Rule missing 'id' field.")
            
        when = rule_dict.get("when", {})
        self.intent = when.get("intent")
        if not self.intent:
            raise RuleSyntaxError(f"Rule {self.rule_id} missing 'when.intent' field.")
            
        self.confidence_gte = float(when.get("confidence_gte", 0.0))
        self.custom_predicate = when.get("custom")
        
        then = rule_dict.get("then", {})
        self.action = then.get("action")
        if not self.action:
            raise RuleSyntaxError(f"Rule {self.rule_id} missing 'then.action' field.")
        self.priority = int(then.get("priority", 50))
        self.action_category = str(then.get("action_category", "MUTATE")).upper()
        self.default_verdict = str(then.get("default_verdict", "EXECUTE")).upper()
        
        # Meta
        self.severity = str(rule_dict.get("severity", "MEDIUM")).upper()
        self.rationale = str(rule_dict.get("rationale", ""))
        
        budget = rule_dict.get("budget", {})
        self.max_per_session = int(budget.get("max_per_session", 1))
        self.cooldown_seconds = int(budget.get("cooldown_seconds", 30))

class RuleLoader:
    @staticmethod
    def load_rules(rules_dir: str) -> List[PolicyRule]:
        rules = []
        if not os.path.exists(rules_dir):
            logger.warning(f"Rules directory not found at {rules_dir}, returning empty ruleset.")
            return rules
            
        for root, _, files in os.walk(rules_dir):
            for file in sorted(files):
                if file.endswith(".yaml") or file.endswith(".yml"):
                    file_path = os.path.join(root, file)
                    logger.info(f"Loading rules from {file_path}")
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if isinstance(data, list):
                                for r_dict in data:
                                    rules.append(PolicyRule(r_dict))
                    except Exception as e:
                        raise RuleSyntaxError(f"Failed to load rules from {file_path}: {e}")
        return rules
