import json
from typing import Any

class JSONRenderer:
    def render(self, data: dict[str, Any]) -> str:
        return json.dumps(data, indent=2, default=str)
