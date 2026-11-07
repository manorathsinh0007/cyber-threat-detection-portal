"""
AEGIS High-Level Real-World Cyber Threat Detection System
Active Defense, Firewall Rule Orchestrator & Process Isolation
"""

import subprocess
import time
import psutil
from typing import Dict, List, Any, Optional

class ActiveDefenseSystem:
    def __init__(self):
        # Quarantine store: ip -> metadata
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        # Terminated processes history
        self.isolated_processes: List[Dict[str, Any]] = []
        # Audit log
        self.defense_log: List[Dict[str, Any]] = []

    def block_ip(self, ip_str: str, reason: str = "SOC Manual Block") -> Dict[str, Any]:
        """
        Quarantine and block an IP address. Attempts to add a real Windows Firewall rule,
        and records it in the AEGIS quarantine table.
        """
        now = time.time()
        rule_name = f"AEGIS_BLOCK_{ip_str.replace('.', '_')}"
        
        # 1. Attempt Windows Firewall execution
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_str}'
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_str}'
        
        fw_applied = False
        fw_msg = ""
        try:
            res_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True, timeout=3)
            res_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True, timeout=3)
            if "Ok." in res_in.stdout or res_in.returncode == 0:
                fw_applied = True
                fw_msg = "Windows Defender Firewall rule active."
            else:
                fw_msg = res_in.stderr.strip() or "Standard user privileges (elevated admin required for kernel firewall rule)."
        except Exception as e:
            fw_msg = f"Firewall command failed: {e}"

        record = {
            "ip": ip_str,
            "rule_name": rule_name,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason,
            "firewall_rule_applied": fw_applied,
            "firewall_msg": fw_msg,
            "command_hint": f"{cmd_in} && {cmd_out}"
        }
        self.blocked_ips[ip_str] = record
        self.defense_log.insert(0, {
            "action": "BLOCK_IP",
            "target": ip_str,
            "status": "ENFORCED" if fw_applied else "QUARANTINED",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": record
        })

        return record

    def unblock_ip(self, ip_str: str) -> Dict[str, Any]:
        """Remove IP from quarantine and delete Windows Firewall rule."""
        rule_name = f"AEGIS_BLOCK_{ip_str.replace('.', '_')}"
        cmd_del_in = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
        cmd_del_out = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'

        try:
            subprocess.run(cmd_del_in, shell=True, capture_output=True, timeout=2)
            subprocess.run(cmd_del_out, shell=True, capture_output=True, timeout=2)
        except Exception:
            pass

        if ip_str in self.blocked_ips:
            del self.blocked_ips[ip_str]

        self.defense_log.insert(0, {
            "action": "UNBLOCK_IP",
            "target": ip_str,
            "status": "RESTORED",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": f"IP {ip_str} removed from quarantine."
        })

        return {"status": "SUCCESS", "unblocked_ip": ip_str}

    def isolate_process(self, pid: int, reason: str = "SOC Threat Containment") -> Dict[str, Any]:
        """
        Immediately terminate a rogue or compromised process by PID.
        """
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_exe = proc.exe()
            proc.terminate()
            time.sleep(0.1)
            if proc.is_running():
                proc.kill()

            record = {
                "pid": pid,
                "name": proc_name,
                "exe": proc_exe,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason,
                "status": "TERMINATED"
            }
            self.isolated_processes.append(record)
            self.defense_log.insert(0, {
                "action": "KILL_PROCESS",
                "target": f"PID {pid} ({proc_name})",
                "status": "CONTAINED",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "details": record
            })
            return {"status": "SUCCESS", "record": record}

        except psutil.NoSuchProcess:
            return {"status": "ERROR", "message": f"Process PID {pid} no longer exists."}
        except psutil.AccessDenied:
            return {"status": "ERROR", "message": f"Access denied terminating PID {pid} (System Protected Process)."}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def is_blocked(self, ip_str: str) -> bool:
        return ip_str in self.blocked_ips

    def get_status(self) -> Dict[str, Any]:
        return {
            "active_quarantined_ips": list(self.blocked_ips.values()),
            "isolated_processes": self.isolated_processes[-20:],
            "defense_audit_log": self.defense_log[-30:]
        }

# Global singleton
active_defense = ActiveDefenseSystem()
