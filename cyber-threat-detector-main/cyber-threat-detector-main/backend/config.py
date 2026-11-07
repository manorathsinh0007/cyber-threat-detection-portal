"""
AEGIS High-Level Real-World Cyber Threat Detection System
Configuration & Threat Intelligence Knowledge Base
"""

import os
from typing import Dict, List, Set

# Server Configuration
HOST: str = os.getenv("AEGIS_HOST", "0.0.0.0")
PORT: int = int(os.getenv("AEGIS_PORT", 8000))
MONITOR_INTERVAL_SECONDS: float = float(os.getenv("AEGIS_MONITOR_INTERVAL", 1.5))

# MITRE ATT&CK Knowledge Base Mapping
MITRE_ATTACK_MATRIX = {
    "PORT_SCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary attempting to get a listing of services running on remote hosts."
    },
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempting to guess credentials through repeated automated attempts."
    },
    "C2_BEACONING": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversary communicating with command and control infrastructure at regular intervals."
    },
    "DATA_EXFILTRATION": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Anomalous high-volume outbound data flow detected to external host."
    },
    "DDOS_FLOOD": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "description": "High rate of connection requests or SYN packets overwhelming network stack."
    },
    "SUSPICIOUS_PROCESS": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Scripting or unauthorized executable initiating external network connections."
    },
    "CLEARTEXT_CREDENTIALS": {
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: In Files / Traffic",
        "tactic": "Credential Access",
        "description": "Transmission of credentials over legacy unencrypted protocols (FTP, Telnet, HTTP)."
    },
    "RANSOMWARE_COMMUNICATION": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Connection to known ransomware payment gateway or key exchange server."
    }
}

# Known Dangerous & Sensitive Network Ports
DANGEROUS_PORTS: Dict[int, Dict[str, str]] = {
    21: {"name": "FTP (Cleartext)", "risk": "MEDIUM", "reason": "Cleartext authentication protocol susceptible to sniffing"},
    23: {"name": "Telnet (Cleartext)", "risk": "HIGH", "reason": "Unencrypted administrative terminal access"},
    69: {"name": "TFTP", "risk": "MEDIUM", "reason": "Trivial File Transfer with zero authentication"},
    135: {"name": "MS RPC", "risk": "HIGH", "reason": "Frequently targeted for remote code execution (EternalBlue/WannaCry)"},
    137: {"name": "NetBIOS Name", "risk": "MEDIUM", "reason": "Exposes local network workgroup enumeration"},
    138: {"name": "NetBIOS Datagram", "risk": "MEDIUM", "reason": "NetBIOS broadcast leak"},
    139: {"name": "NetBIOS Session", "risk": "HIGH", "reason": "Legacy Windows SMB session service"},
    445: {"name": "Microsoft SMB", "risk": "CRITICAL", "reason": "Common ransomware propagation vector over WAN"},
    1433: {"name": "MS SQL Server", "risk": "HIGH", "reason": "Database port exposed to unauthorized access"},
    1434: {"name": "MS SQL Monitor", "risk": "MEDIUM", "reason": "SQL Server resolution and probe target"},
    3306: {"name": "MySQL DB", "risk": "HIGH", "reason": "Direct relational database access exposed"},
    3389: {"name": "RDP (Remote Desktop)", "risk": "HIGH", "reason": "Target for brute force and BlueKeep exploits"},
    4444: {"name": "Metasploit Default C2", "risk": "CRITICAL", "reason": "Standard default Metasploit reverse meterpreter payload port"},
    5432: {"name": "PostgreSQL", "risk": "HIGH", "reason": "Direct relational database port"},
    6667: {"name": "IRC (Internet Relay Chat)", "risk": "CRITICAL", "reason": "Classic C2 botnet channel for zombie communication"},
    8333: {"name": "Bitcoin Node / Mining", "risk": "HIGH", "reason": "Cryptojacking or unauthorized crypto mining activity"},
    31337: {"name": "Back Orifice Elite", "risk": "CRITICAL", "reason": "Classic trojan horse backdoor port"},
    5555: {"name": "Android ADB", "risk": "HIGH", "reason": "Android Debug Bridge exposed without authorization"}
}

# Known Safe Standard Ports
SAFE_PORTS: Set[int] = {53, 80, 123, 443, 853, 8080, 8443}

# Known Suspicious Executable Names for Network Activity
SUSPICIOUS_EXECUTABLE_NAMES: Set[str] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "vssadmin.exe", "bitsadmin.exe", "rundll32.exe",
    "regsvr32.exe", "schtasks.exe", "nc.exe", "ncat.exe", "mimikatz.exe"
}

# Threat Scoring Thresholds
PORT_SCAN_THRESHOLD_PORTS = 4       # Distinct ports hit by single IP in window
PORT_SCAN_WINDOW_SECONDS = 5.0      # Sliding window for scan detection
C2_BEACON_MIN_SAMPLES = 4           # Minimum samples to evaluate beaconing regularity
C2_BEACON_MAX_JITTER_RATIO = 0.18   # Maximum standard deviation / mean to classify as automated beacon
EXFILTRATION_BYTES_THRESHOLD = 50 * 1024 * 1024  # 50MB outbound in short duration
