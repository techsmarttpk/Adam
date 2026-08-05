import json
import yaml
import jsonschema
from pathlib import Path
import sys

def main():
    schema_path = Path("rules/schema/rule.schema.json")
    with schema_path.open() as f:
        schema = json.load(f)

    rules_dir = Path("rules/default")
    errors = 0

    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        print(f"Validating {yaml_file.name}...")
        with yaml_file.open() as f:
            rules = yaml.safe_load(f)
            if not isinstance(rules, list):
                print(f"  {yaml_file.name} is not a list")
                errors += 1
                continue
            
            for i, rule in enumerate(rules):
                try:
                    jsonschema.validate(instance=rule, schema=schema)
                except jsonschema.exceptions.ValidationError as e:
                    print(f"  Validation error in rule {i} (id: {rule.get('id')}): {e.message}")
                    errors += 1

    if errors == 0:
        print("All rules validated successfully against the schema.")
        sys.exit(0)
    else:
        print(f"Validation failed with {errors} errors.")
        sys.exit(1)

if __name__ == '__main__':
    main()
