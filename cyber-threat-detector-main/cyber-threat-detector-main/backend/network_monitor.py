"""
AEGIS High-Level Real-World Cyber Threat Detection System
Live Network Telemetry, Socket Sniffer & Process Correlation Engine
"""

import time
import socket
import psutil
from typing import Dict, List, Any, Optional, Set
from backend.geo_service import geo_service

class RealNetworkMonitor:
    def __init__(self):
        self.selected_interface: Optional[str] = None
        self.last_poll_time: float = time.time()
        self.last_io_counters = psutil.net_io_counters()
        self.last_per_nic_counters = psutil.net_io_counters(pernic=True)
        
        # Track seen connections to identify new flows
        self.previous_connections: Set[str] = set()
        
        # Aggregated telemetry metrics
        self.total_packets_observed: int = 0
        self.bytes_sent_rate: float = 0.0
        self.bytes_recv_rate: float = 0.0
        self.packets_sent_rate: float = 0.0
        self.packets_recv_rate: float = 0.0

        # Cache of PID -> process details to prevent heavy repeated WMI queries
        self._proc_cache: Dict[int, Dict[str, Any]] = {}
        self._proc_cache_ttl: float = 5.0
        self._proc_cache_timestamp: float = 0.0

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """
        Enumerate all physical, wireless, virtual, and loopback network adapters.
        """
        interfaces_data = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_per_nic = psutil.net_io_counters(pernic=True)

        for name, addr_list in addrs.items():
            ipv4 = None
            ipv6 = None
            mac = None

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif addr.family == socket.AF_INET6:
                    ipv6 = addr.address
                elif hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                    mac = addr.address
                elif addr.family == -1: # Windows MAC fallback
                    mac = addr.address

            stat = stats.get(name)
            is_up = stat.isup if stat else False
            speed_mbps = stat.speed if stat else 0
            
            nic_io = io_per_nic.get(name)
            bytes_sent = nic_io.bytes_sent if nic_io else 0
            bytes_recv = nic_io.bytes_recv if nic_io else 0
            pkts_sent = nic_io.packets_sent if nic_io else 0
            pkts_recv = nic_io.packets_recv if nic_io else 0

            interfaces_data.append({
                "name": name,
                "ipv4": ipv4 or "Unassigned",
                "ipv6": ipv6 or "None",
                "mac": mac or "Unknown",
                "is_up": is_up,
                "speed_mbps": speed_mbps,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "packets_sent": pkts_sent,
                "packets_recv": pkts_recv,
                "is_active": (name == self.selected_interface) if self.selected_interface else is_up
            })

        return interfaces_data

    def select_interface(self, interface_name: str) -> bool:
        """Select a specific network interface to focus telemetry on."""
        addrs = psutil.net_if_addrs()
        if interface_name in addrs:
            self.selected_interface = interface_name
            return True
        return False

    def _resolve_process(self, pid: Optional[int]) -> Dict[str, Any]:
        """Correlate connection socket with OS process details."""
        if not pid or pid <= 0:
            return {
                "pid": 0,
                "name": "System / Kernel",
                "exe": "C:\\Windows\\System32\\ntoskrnl.exe",
                "status": "kernel",
                "username": "SYSTEM"
            }

        now = time.time()
        if now - self._proc_cache_timestamp > self._proc_cache_ttl:
            self._proc_cache.clear()
            self._proc_cache_timestamp = now

        if pid in self._proc_cache:
            return self._proc_cache[pid]

        try:
            p = psutil.Process(pid)
            info = {
                "pid": pid,
                "name": p.name(),
                "exe": p.exe(),
                "status": p.status(),
                "username": p.username() if hasattr(p, 'username') else "Unknown"
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            info = {
                "pid": pid,
                "name": f"Process-{pid}",
                "exe": "Protected / Terminated",
                "status": "terminated",
                "username": "Unknown"
            }

        self._proc_cache[pid] = info
        return info

    def capture_network_snapshot(self) -> Dict[str, Any]:
        """
        High-performance capture of live network state:
        - Real bandwidth throughput (KB/s, pps)
        - All active TCP/UDP connections with correlated processes and geolocations
        - Identification of new or listening flows
        """
        now = time.time()
        dt = max(now - self.last_poll_time, 0.1)
        self.last_poll_time = now

        # 1. Update I/O Rates
        current_io = psutil.net_io_counters()
        bytes_sent_delta = max(current_io.bytes_sent - self.last_io_counters.bytes_sent, 0)
        bytes_recv_delta = max(current_io.bytes_recv - self.last_io_counters.bytes_recv, 0)
        pkts_sent_delta = max(current_io.packets_sent - self.last_io_counters.packets_sent, 0)
        pkts_recv_delta = max(current_io.packets_recv - self.last_io_counters.packets_recv, 0)

        self.bytes_sent_rate = bytes_sent_delta / dt
        self.bytes_recv_rate = bytes_recv_delta / dt
        self.packets_sent_rate = pkts_sent_delta / dt
        self.packets_recv_rate = pkts_recv_delta / dt
        self.total_packets_observed += (pkts_sent_delta + pkts_recv_delta)
        self.last_io_counters = current_io

        # 2. Extract Active Connections
        raw_conns = []
        try:
            raw_conns = psutil.net_connections(kind='inet')
        except Exception as e:
            print(f"[!] Warning reading network connections: {e}")

        active_connections: List[Dict[str, Any]] = []
        current_conn_keys: Set[str] = set()
        listening_ports: List[int] = []

        for conn in raw_conns:
            laddr = conn.laddr
            raddr = conn.raddr
            status = conn.status
            pid = conn.pid
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            local_ip = laddr.ip if laddr else "0.0.0.0"
            local_port = laddr.port if laddr else 0
            remote_ip = raddr.ip if raddr else ""
            remote_port = raddr.port if raddr else 0

            if status == "LISTEN":
                listening_ports.append(local_port)

            flow_key = f"{proto}:{local_ip}:{local_port}->{remote_ip}:{remote_port}"
            current_conn_keys.add(flow_key)
            is_new = flow_key not in self.previous_connections

            proc_info = self._resolve_process(pid)
            geo_info = geo_service.lookup(remote_ip) if remote_ip else geo_service.lookup(local_ip)

            item = {
                "flow_id": flow_key,
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip or "0.0.0.0",
                "remote_port": remote_port,
                "status": status,
                "is_new": is_new,
                "pid": pid or 0,
                "process_name": proc_info["name"],
                "process_exe": proc_info["exe"],
                "process_user": proc_info["username"],
                "geo": geo_info,
                "timestamp": now
            }
            active_connections.append(item)

        self.previous_connections = current_conn_keys

        return {
            "timestamp": now,
            "metrics": {
                "bytes_sent_per_sec": round(self.bytes_sent_rate, 2),
                "bytes_recv_per_sec": round(self.bytes_recv_rate, 2),
                "kb_sent_per_sec": round(self.bytes_sent_rate / 1024, 2),
                "kb_recv_per_sec": round(self.bytes_recv_rate / 1024, 2),
                "packets_sent_per_sec": round(self.packets_sent_rate, 2),
                "packets_recv_per_sec": round(self.packets_recv_rate, 2),
                "total_packets": self.total_packets_observed,
                "total_system_sent_mb": round(current_io.bytes_sent / (1024 * 1024), 2),
                "total_system_recv_mb": round(current_io.bytes_recv / (1024 * 1024), 2),
                "active_connections_count": len(active_connections),
                "listening_ports_count": len(set(listening_ports))
            },
            "active_connections": active_connections,
            "listening_ports": sorted(list(set(listening_ports)))
        }

# Global singleton
network_monitor = RealNetworkMonitor()
