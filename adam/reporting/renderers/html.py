import jinja2
from typing import Any

class HTMLRenderer:
    def __init__(self):
        self.template = jinja2.Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADAM Threat Analysis Report - {{ session_id }}</title>
    <style>
        :root {
            --bg: #0e1117;
            --card-bg: #1a1f2c;
            --border: #2d3748;
            --text-main: #f0f4f8;
            --text-muted: #94a3b8;
            --accent: #3b82f6;
            --green: #10b981;
            --red: #ef4444;
            --purple: #8b5cf6;
            --yellow: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: #0e1117;
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 24px;
            border-radius: 10px;
        }
        .header {
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }
        .header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .header .meta {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 4px;
        }
        .badge-pill {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 9999px;
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .badge-treatment { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .badge-control { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid #64748b; }
        .badge-status { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
        .badge-net { background: rgba(147, 197, 253, 0.15); color: #93c5fd; border: 1px solid #3b82f6; }
        .badge-event { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
        .badge-mutation { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px 20px;
        }
        .stat-card .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
        }
        .stat-card .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: #f8fafc;
            margin-top: 4px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 22px;
            margin-bottom: 24px;
        }
        .card h2 {
            font-size: 1.15rem;
            font-weight: 600;
            margin-bottom: 16px;
            color: #e2e8f0;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        /* Key Value Grid */
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px 24px;
            font-size: 0.9rem;
        }
        .meta-item {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        .meta-item .meta-k { color: var(--text-muted); }
        .meta-item .meta-v { color: #f1f5f9; font-weight: 500; font-family: monospace; }

        .tag-list { display: flex; flex-wrap: wrap; gap: 8px; }
        .tag {
            background: #242c3d;
            border: 1px solid #3b4861;
            color: #93c5fd;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-family: monospace;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }
        th, td {
            text-align: left;
            padding: 11px 14px;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: #141824;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
        }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        .row-mutation { border-left: 4px solid #f59e0b; background: rgba(245, 158, 11, 0.03); }
        .row-event { border-left: 4px solid #10b981; background: rgba(16, 185, 129, 0.03); }
        
        .timeline-item {
            background: #151922;
            border: 1px solid #283143;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .timeline-time {
            font-family: monospace;
            color: var(--text-muted);
            font-size: 0.82rem;
        }
        .timeline-content { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .empty-state { color: var(--text-muted); font-style: italic; font-size: 0.9rem; padding: 8px 0; }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div>
            <h1>🛡️ ADAM Threat Intelligence Report</h1>
            <div class="meta">
                Session: <strong style="color: #60a5fa;">{{ session_id }}</strong> | 
                Experiment: <strong>{{ experiment_id }}</strong>
            </div>
        </div>
        <div style="display: flex; gap: 8px; align-items: center;">
            {% if config and config.network_mode %}
            <span class="badge-pill badge-net">NET: {{ config.network_mode }}</span>
            {% endif %}
            <span class="badge-pill {% if arm == 'TREATMENT' %}badge-treatment{% else %}badge-control{% endif %}">ARM: {{ arm }}</span>
            <span class="badge-pill badge-status">{{ status }}</span>
        </div>
    </div>

    <!-- Stats Top Grid -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Events Analyzed</div>
            <div class="stat-value">{{ metrics.events_count if metrics else timeline|length }}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Mutations Applied</div>
            <div class="stat-value">{{ metrics.mutations_count if metrics else 0 }}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Decisions Evaluated</div>
            <div class="stat-value">{{ metrics.decisions_count if metrics else decisions|length }}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">MITRE Techniques</div>
            <div class="stat-value">{{ attck_coverage|length }}</div>
        </div>
    </div>

    <!-- Sample & Environment Profile -->
    <div class="card">
        <h2>📦 Sample & Target Environment Profile</h2>
        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-k">Sample Name:</span>
                <span class="meta-v">{{ sample.filename if sample and sample.filename else 'smoke_sample.exe' }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-k">SHA-256 Hash:</span>
                <span class="meta-v" style="font-size: 0.8rem; word-break: break-all;">{{ sample.sha256 if sample and sample.sha256 else 'N/A' }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-k">File Type:</span>
                <span class="meta-v">{{ sample.file_type if sample and sample.file_type else 'PE32 / Windows Binary' }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-k">VM Profile:</span>
                <span class="meta-v">{{ config.vm_profile if config and config.vm_profile else 'bare_control' }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-k">Started At:</span>
                <span class="meta-v">{{ started_at or 'N/A' }}</span>
            </div>
            <div class="meta-item">
                <span class="meta-k">Ended At:</span>
                <span class="meta-v">{{ ended_at or 'N/A' }}</span>
            </div>
        </div>
    </div>

    <!-- MITRE ATT&CK Matrix -->
    <div class="card">
        <h2>🛡️ MITRE ATT&CK® Coverage</h2>
        {% if attck_coverage %}
        <div class="tag-list">
            {% for item in attck_coverage %}
            <span class="tag">{{ item }}</span>
            {% endfor %}
        </div>
        {% else %}
        <div class="empty-state">No ATT&CK techniques mapped for this session.</div>
        {% endif %}
    </div>

    <!-- IOCs and Planted Lures -->
    <div class="card">
        <h2>🔍 Indicators of Compromise (IOCs) & Planted Artifacts</h2>
        {% if iocs %}
        <table>
            <thead>
                <tr>
                    <th style="width: 140px;">Source</th>
                    <th>Target / Path</th>
                    <th style="width: 160px;">Operation</th>
                </tr>
            </thead>
            <tbody>
                {% for ioc in iocs %}
                <tr class="{% if ioc.source == 'mutation' %}row-mutation{% else %}row-event{% endif %}">
                    <td><span class="badge-pill {% if ioc.source == 'mutation' %}badge-mutation{% else %}badge-event{% endif %}">{{ ioc.source|upper }}</span></td>
                    <td style="font-family: monospace; color: #cbd5e1; word-break: break-all;">{{ ioc.target }}</td>
                    <td style="color: #94a3b8;">{{ ioc.operation or '—' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="empty-state">No IOCs extracted for this session.</div>
        {% endif %}
    </div>

    <!-- Policy Decisions & Rules Evaluated -->
    {% if decisions %}
    <div class="card">
        <h2>⚙️ Policy Engine & Deception Decisions Log</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 120px;">Rule ID</th>
                    <th style="width: 130px;">Verdict</th>
                    <th>Action</th>
                    <th>Rationale</th>
                </tr>
            </thead>
            <tbody>
                {% for d in decisions[:15] %}
                <tr>
                    <td style="font-family: monospace; color: #93c5fd; font-weight: 600;">{{ d.rule_id }}</td>
                    <td>
                        <span class="badge-pill {% if d.verdict == 'EXECUTE' %}badge-status{% elif 'SUPPRESSED' in d.verdict %}badge-treatment{% else %}badge-control{% endif %}">
                            {{ d.verdict }}
                        </span>
                    </td>
                    <td style="font-family: monospace; color: #cbd5e1;">{{ d.action }}</td>
                    <td style="color: #94a3b8; font-size: 0.82rem;">{{ d.rationale }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Chronological Timeline -->
    <div class="card">
        <h2>⏱️ Behavioral Timeline (Events & Applied Mutations)</h2>
        {% if timeline %}
        <div>
            {% for item in timeline %}
            <div class="timeline-item">
                <div class="timeline-content">
                    {% if item.type == 'SemanticEvent' %}
                    <span class="badge-pill badge-event">EVENT</span>
                    <strong style="color: #f0f4f8;">{{ item.intent }}</strong>
                    <span style="color: #34d399; font-size: 0.75rem; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; padding: 2px 6px; border-radius: 4px;">{{ "%.0f"|format(item.confidence * 100) }}% CONF</span>
                    {% else %}
                    <span class="badge-pill badge-mutation">MUTATION</span>
                    <strong style="color: #f0f4f8;">{{ item.primitive }}</strong>
                    <span style="color: #60a5fa; font-size: 0.75rem; background: rgba(59, 130, 246, 0.15); border: 1px solid #3b82f6; padding: 2px 6px; border-radius: 4px;">{{ item.status }}</span>
                    {% endif %}
                </div>
                <span class="timeline-time">{{ item.time }}</span>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="empty-state">No timeline activity recorded for this session.</div>
        {% endif %}
    </div>
</body>
</html>
""")

    def render(self, data: dict[str, Any]) -> str:
        return self.template.render(
            session_id=data.get("session_id", "N/A"),
            experiment_id=data.get("experiment_id", "N/A"),
            arm=data.get("arm", "N/A"),
            status=data.get("status", "COMPLETED"),
            started_at=data.get("started_at", "N/A"),
            ended_at=data.get("ended_at", "N/A"),
            sample=data.get("sample", {}),
            config=data.get("config", {}),
            metrics=data.get("metrics", {}),
            attck_coverage=data.get("attck_coverage", []),
            iocs=data.get("iocs", []),
            decisions=data.get("decisions", []),
            timeline=data.get("timeline", []),
            detection_risk=data.get("detection_risk", []),
        )


