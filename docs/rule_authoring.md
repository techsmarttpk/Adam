# Rule & Primitive Authoring Guide

This guide describes how to extend the ADAM Policy Engine and Adaptive Deception Engine.

## 1. Adding a New Rule
Rules are stored in `rules/default/*.yaml` grouped by tactic family (e.g. `credentials.yaml`, `recon.yaml`) and validated against `rules/schema/rule.schema.json`.

To add a new rule:
```yaml
- id: RULE-020
  version: "1.0.0"
  description: >
    Crypto wallet search
  when:
    intent: CRED_WALLET_SEARCH
    confidence_gte: 0.80
  then:
    action: PLANT_DECOY_WALLET
    priority: 80
  budget:
    max_per_session: 1
    cooldown_seconds: 60
```
Every `then.action` string must map to a registered primitive in the deception catalogue.

## 2. Declarative DSL vs. Custom Predicates
- **Built-in DSL**: Use standard declarative comparisons (`intent`, `confidence_gte`, `confidence_lte`, `severity`, `feature_equals`) directly inside the `when:` block for basic checks.
- **Custom Predicates**: Use `when.custom: "predicates.<fn_name>"` when logic requires complex computation over event features or context.

### Worked Example (`repeated_ldap_failure`)
In `adam/policy/predicates/builtin.py`:
```python
from adam.policy.predicates import predicate

@predicate("repeated_ldap_failure")
def repeated_ldap_failure(event, _context) -> bool:
    """True if 2+ failed LDAP attempts occurred without a success."""
    ldap_attempts = event.features.get("ldap_attempts", 0)
    all_failed = event.features.get("all_failed", False)
    return ldap_attempts >= 2 and bool(all_failed)
```

In YAML:
```yaml
  when:
    intent: RECON_DOMAIN_CONTROLLER
    confidence_gte: 0.75
    custom: "predicates.repeated_ldap_failure"
```

## 3. Adding a Deception Primitive
Primitives execute deceptive guest mutations. The catalogue uses a decentralized decorator-based registry pattern (`@register_primitive`), auto-discovered by `catalogue.py`.

### Worked Example (`PLANT_DECOY_WALLET`)
In `adam/deception/primitives/filesystem_lures.py`:
```python
from adam.contracts.enums import ChangeKind, MutationStatus
from adam.contracts.mutation import Change, MutationResult
from adam.deception.catalogue import register_primitive
from adam.deception.plausibility import combine, score_naming_consistency, score_timestamp_consistency
from adam.deception.primitives.base import DeceptionPrimitive

@register_primitive("PLANT_DECOY_WALLET")
class PlantDecoyWallet(DeceptionPrimitive):
    name = "PlantDecoyWallet"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        return [
            Change(
                kind=ChangeKind.FILE,
                target=r"C:\Users\Admin\AppData\Roaming\Bitcoin\wallet.dat",
                operation="CREATE",
                value="size=131072,timestamp=1000",
            ),
        ]

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        ts = score_timestamp_consistency(is_post_boot_write=False)
        name = score_naming_consistency(matches_locale_convention=True)
        return combine(ts, name), "Fake cryptocurrency wallet planted"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in reversed(mutation.changes):
            await self._channel.apply_mutation(change.kind.value, change.target, "DELETE", None)
        mutation.status = MutationStatus.REVERTED
        return mutation
```
