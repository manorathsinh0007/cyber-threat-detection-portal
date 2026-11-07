"""
AEGIS High-Level Real-World Cyber Threat Detection System
Active Network Port Scanner & Service Reconnaissance Engine
"""

import asyncio
import socket
import time
from typing import Dict, List, Any, Callable, Optional
from backend.config import DANGEROUS_PORTS

# Common ports to scan in standard reconnaissance
STANDARD_PROBE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 4444, 5000, 5432, 5900,
    6379, 6667, 8000, 8080, 8443, 8888, 9000, 9200, 27017
]

SERVICE_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MS SQL", 1521: "Oracle DB",
    3306: "MySQL", 3389: "RDP Remote Desktop", 4444: "Metasploit Listener",
    5000: "UPnP / Web Service", 5432: "PostgreSQL", 5900: "VNC Remote Access",
    6379: "Redis In-Memory Store", 6667: "IRC Chat", 8000: "HTTP Dev Server",
    8080: "HTTP Proxy / Alternate", 8443: "HTTPS Alternate",
    8888: "Jupyter / HTTP Web", 9000: "SonarQube / PHP-FPM",
    9200: "Elasticsearch REST", 27017: "MongoDB NoSQL"
}

class RealNetworkScanner:
    def __init__(self):
        self.is_scanning: bool = False
        self.current_scan_id: Optional[str] = None

    async def scan_target(
        self,
        target_host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 0.6,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Asynchronously scans target IP for open ports, grabs banners, and rates exposure risk.
        """
        self.is_scanning = True
        scan_id = f"SCAN-{int(time.time())}"
        self.current_scan_id = scan_id

        target_ports = ports or STANDARD_PROBE_PORTS
        total_ports = len(target_ports)
        open_ports: List[Dict[str, Any]] = []

        # Resolve hostname
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror as e:
            self.is_scanning = False
            return {
                "scan_id": scan_id,
                "target": target_host,
                "error": f"Failed to resolve target: {e}",
                "open_ports": []
            }

        start_time = time.time()
        completed = 0

        # Scan ports concurrently with semaphore to prevent socket exhaustion
        sem = asyncio.Semaphore(30)

        async def probe_port(port: int):
            nonlocal completed
            async with sem:
                result = await self._check_port(target_ip, port, timeout)
                completed += 1

                if result:
                    open_ports.append(result)

                if progress_cb:
                    progress_cb({
                        "scan_id": scan_id,
                        "target": target_host,
                        "target_ip": target_ip,
                        "progress_percent": round((completed / total_ports) * 100, 1),
                        "ports_scanned": completed,
                        "total_ports": total_ports,
                        "latest_result": result,
                        "is_complete": (completed == total_ports)
                    })

        tasks = [probe_port(p) for p in target_ports]
        await asyncio.gather(*tasks)

        elapsed = round(time.time() - start_time, 2)
        self.is_scanning = False

        # Sort open ports
        open_ports.sort(key=lambda x: x["port"])

        return {
            "scan_id": scan_id,
            "target": target_host,
            "target_ip": target_ip,
            "elapsed_seconds": elapsed,
            "total_ports_probed": total_ports,
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "status": "COMPLETED"
        }

    async def _check_port(self, target_ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
        conn = asyncio.open_connection(target_ip, port)
        try:
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = ""
            # Quick non-blocking attempt to read banner
            try:
                # Send generic probe for HTTP or read initial welcome prompt
                if port in (80, 8000, 8080):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(256), timeout=0.3)
                banner = banner_data.decode("utf-8", errors="ignore").strip()
            except Exception:
                banner = ""

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service_name = SERVICE_PORT_NAMES.get(port, "Unknown Service")
            is_dangerous = port in DANGEROUS_PORTS
            risk_level = "SAFE"
            if is_dangerous:
                risk_level = DANGEROUS_PORTS[port]["risk"]
            elif port in (80, 443, 8080):
                risk_level = "LOW"
            elif port in (22, 3389):
                risk_level = "MEDIUM"

            return {
                "port": port,
                "protocol": "TCP",
                "service": service_name,
                "banner": banner[:80] if banner else "No initial banner",
                "risk_level": risk_level,
                "is_dangerous": is_dangerous,
                "recommendation": DANGEROUS_PORTS[port]["reason"] if is_dangerous else "Verify authentication and TLS encryption"
            }

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

# Global singleton
network_scanner = RealNetworkScanner()
