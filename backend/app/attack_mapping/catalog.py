from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueDefinition:
    technique_id: str
    tactic: str
    name: str
    description: str


CURATED_TECHNIQUES = {
    "T1059.001": TechniqueDefinition(
        "T1059.001", "execution", "PowerShell", "Execution through PowerShell commands."
    ),
    "T1059.003": TechniqueDefinition(
        "T1059.003", "execution", "Windows Command Shell", "Execution through cmd.exe."
    ),
    "T1105": TechniqueDefinition(
        "T1105", "command-and-control", "Ingress Tool Transfer", "Transfer of files or tools."
    ),
    "T1071.001": TechniqueDefinition(
        "T1071.001", "command-and-control", "Web Protocols", "C2 over HTTP or HTTPS."
    ),
    "T1071.004": TechniqueDefinition(
        "T1071.004", "command-and-control", "DNS", "C2 communication using DNS."
    ),
    "T1573": TechniqueDefinition(
        "T1573", "command-and-control", "Encrypted Channel", "Encrypted C2 communication."
    ),
    "T1547.001": TechniqueDefinition(
        "T1547.001", "persistence", "Registry Run Keys / Startup Folder", "Logon autostart."
    ),
    "T1055": TechniqueDefinition(
        "T1055", "defense-evasion", "Process Injection", "Execution inside another process."
    ),
    "T1027": TechniqueDefinition(
        "T1027", "defense-evasion", "Obfuscated Files or Information", "Obfuscated payloads."
    ),
    "T1003": TechniqueDefinition(
        "T1003", "credential-access", "OS Credential Dumping", "Credential extraction."
    ),
    "T1555": TechniqueDefinition(
        "T1555", "credential-access", "Credentials from Password Stores", "Password-store access."
    ),
    "T1056.001": TechniqueDefinition(
        "T1056.001", "credential-access", "Keylogging", "Capture of keyboard input."
    ),
    "T1082": TechniqueDefinition(
        "T1082", "discovery", "System Information Discovery", "Host information discovery."
    ),
    "T1083": TechniqueDefinition(
        "T1083", "discovery", "File and Directory Discovery", "Filesystem enumeration."
    ),
    "T1041": TechniqueDefinition(
        "T1041", "exfiltration", "Exfiltration Over C2 Channel", "Data exfiltration over C2."
    ),
    "T1498": TechniqueDefinition(
        "T1498", "impact", "Network Denial of Service", "Disruption using network traffic."
    ),
}


MALWARE_TECHNIQUE_MAP: dict[str, tuple[str, ...]] = {
    "emotet": ("T1059.001", "T1105", "T1055", "T1003", "T1071.001"),
    "trickbot": ("T1059.003", "T1055", "T1003", "T1082", "T1071.001"),
    "qakbot": ("T1059.001", "T1105", "T1055", "T1555", "T1071.001"),
    "qbot": ("T1059.001", "T1105", "T1055", "T1555", "T1071.001"),
    "dridex": ("T1059.001", "T1055", "T1056.001", "T1071.001"),
    "cobalt strike": ("T1059.001", "T1105", "T1055", "T1573"),
    "cobaltstrike": ("T1059.001", "T1105", "T1055", "T1573"),
    "redline": ("T1555", "T1082", "T1041", "T1071.001"),
    "lokibot": ("T1555", "T1056.001", "T1041", "T1071.001"),
    "agent tesla": ("T1056.001", "T1555", "T1041", "T1071.001"),
    "remcos": ("T1059.003", "T1547.001", "T1083", "T1071.001"),
    "njrat": ("T1059.003", "T1547.001", "T1082", "T1071.001"),
    "formbook": ("T1056.001", "T1555", "T1041", "T1071.001"),
    "asyncrat": ("T1059.003", "T1547.001", "T1105", "T1573"),
    "gozi": ("T1055", "T1003", "T1555", "T1071.001"),
    "icedid": ("T1059.001", "T1105", "T1055", "T1071.001"),
    "pikabot": ("T1059.001", "T1105", "T1027", "T1071.001"),
    "sliver": ("T1059.001", "T1105", "T1573", "T1071.004"),
    "mirai": ("T1082", "T1071.001", "T1498"),
    "botnet-c2": ("T1071.001", "T1573"),
}


def techniques_for_family(family: str | None) -> list[str]:
    if not family:
        return []
    normalized = " ".join(family.lower().replace("_", " ").replace("-", " ").split())
    for known_family, techniques in MALWARE_TECHNIQUE_MAP.items():
        if known_family in normalized:
            return list(techniques)
    return []
