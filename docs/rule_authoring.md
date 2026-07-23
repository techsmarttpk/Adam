# Rule Authoring Guide

This guide covers how to extend the ADAM Policy Engine and Adaptive Deception Engine. The architecture relies heavily on declarative rules and auto-discovered plugins to prevent merge conflicts and central bottlenecks.

## 1. Adding a New Rule
Rules live in `rules/default/*.yaml` and are grouped by tactic family (e.g., `recon.yaml`, `credentials.yaml`). To add a rule:
1. Pick the relevant YAML file or create a new one.
2. Define the rule matching the JSON schema (`rules/schema/rule.schema.json`).
3. Example:
   ```yaml
   - id: RULE-101
     version: "1.0.0"
     description: Example rule for a new intent.
     when:
       intent: NEW_INTENT_NAME
       confidence_gte: 0.75
     then:
       action: MY_NEW_ACTION
       priority: 50
     budget:
       max_per_session: 1
       cooldown_seconds: 60
   ```
4. All `then.action` strings must map exactly to a registered primitive (see below).

## 2. DSL vs. Custom Predicates
The `when` block supports declarative checks (`intent`, `confidence_gte`, `feature_equals`).
- **Use the DSL** for straightforward comparisons (e.g., matching a specific string, threshold checks). This keeps the logic transparent and easy to review without Python code.
- **Use a Custom Predicate** (`when.custom: "predicates.my_func"`) only when the condition requires complex logic, loops, or aggregations over the event features (e.g., `distinct_registry_keys_over`). Custom predicates must be pure functions added to `adam/policy/predicates/builtin.py` (or a similar module).

## 3. Adding a New Deception Primitive
Primitives execute the decoy actions on the guest system. We use a decentralized registry pattern:
1. Create a new file or add a class in `adam/deception/primitives/`.
2. Inherit from `DeceptionPrimitive`.
3. Implement `_build_changes`, `_plausibility`, and `revert_async`.
4. Decorate the class with `@register_primitive("MY_NEW_ACTION")`.
5. The `catalogue.py` auto-discovers all files in the `primitives` package, so no central list needs to be updated.

```python
from adam.deception.catalogue import register_primitive
from adam.deception.primitives.base import DeceptionPrimitive

@register_primitive("MY_NEW_ACTION")
class MyNewLure(DeceptionPrimitive):
    # Implement abstract methods
```

## Known Limitations
- **Revert Untested Against Real VM**: The `revert_async` logic for deception primitives is currently only unit-tested against the `FakeGuestChannel`. Real VM rollback/teardown integration is pending the sandbox controller module.
- **Partial Catalogue Implementation**: Currently, only a subset of primitives from the broader catalogue are implemented.
- **Predicates Cannot Receive YAML Parameters**: `when.custom` takes only a function name. Complex parameterization requires extending the rule schema or reading from `event.features`.
