import json
from typing import Any

class MarkdownRenderer:
    def render(self, data: dict[str, Any]) -> str:
        lines = []
        if "experiment_id" in data and "delta_semantic_events" in data:
            lines.append(f"# Yield Comparison: {data['experiment_id']}")
            lines.append(f"**Control Session**: {data['control_session']}")
            lines.append(f"**Treatment Session**: {data['treatment_session']}")
            lines.append(f"**Delta Semantic Events**: {data['delta_semantic_events']}")
            
            lines.append("## Distinct Intents Yield")
            for i in data["distinct_intents_yield"]:
                lines.append(f"- {i}")
                
            lines.append("## Distinct Networks Yield")
            for n in data["distinct_networks_yield"]:
                lines.append(f"- {n}")
        else:
            lines.append(f"# Session Report: {data['session_id']}")
            lines.append(f"**Experiment**: {data['experiment_id']} ({data['arm']})")
            
            lines.append("## ATT&CK Coverage")
            for c in data["attck_coverage"]:
                lines.append(f"- {c}")
                
            lines.append("## Detection Risk")
            for r in data["detection_risk"]:
                lines.append(f"- Primitive: {r.get('primitive')}, Plausibility: {r.get('plausibility_score')}")
                
            lines.append("## IOCs")
            for ioc in data["iocs"]:
                lines.append(f"- [{ioc['source']}] {ioc['target']} {ioc.get('operation', '')}")
                
            lines.append("## Timeline")
            for t in data["timeline"]:
                if t["type"] == "SemanticEvent":
                    lines.append(f"- {t['time']} [EVENT] {t['intent']} (Conf: {t['confidence']})")
                else:
                    lines.append(f"- {t['time']} [MUTATION] {t['primitive']} (Status: {t.get('status')})")
                    
        return "\n".join(lines)
