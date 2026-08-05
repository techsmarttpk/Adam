from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    tactic: str
    name: str
    severity: str


MITRE = {

    "T1082": Technique(
        id="T1082",
        tactic="Discovery",
        name="System Information Discovery",
        severity="LOW",
    ),

    "T1547": Technique(
        id="T1547",
        tactic="Persistence",
        name="Boot or Logon Autostart Execution",
        severity="MEDIUM",
    ),

    "T1003": Technique(
        id="T1003",
        tactic="Credential Access",
        name="OS Credential Dumping",
        severity="HIGH",
    ),

}