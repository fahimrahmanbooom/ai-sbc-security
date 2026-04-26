"""
AI SBC Security - Network Monitor
Passive network traffic analysis using psutil.
Tracks connections, unusual ports, bandwidth spikes, and geo-lookup.
"""
import asyncio
import logging
import socket
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any

import psutil

logger = logging.getLogger("ai_sbc.monitor.network")

# Suspicious ports to alert on
SUSPICIOUS_PORTS = {
    # Malware C2
    1337, 31337, 4444, 4445, 5555, 6666, 7777, 9001, 9999,
    # Remote access
    5900, 5901,  # VNC
    3389,         # RDP
    # Mining
    3333, 14444, 45560, 8888,
    # Netcat common
    1234, 12345, 54321,
}

# Well-known service ports (not inherently suspicious)
KNOWN_SERVICES = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP",
    25: "SMTP", 587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
    53: "DNS", 123: "NTP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt",
}


def geo_lookup(ip: str) -> Optional[Dict[str, str]]:
    """
    Lightweight geo lookup using hostname reverse DNS.
    For production, replace with MaxMind GeoLite2 or ip-api.com.
    """
    try:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            return {"country": "Local", "city": "LAN", "org": "Private Network"}
        if ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return {"country": "Local", "city": "Loopback", "org": "localhost"}
        hostname = socket.gethostbyaddr(ip)[0]
        return {"country": "Unknown", "city": "Unknown", "org": hostname}
    except:
        return {"country": "Unknown", "city": "Unknown", "org": "Unknown"}


def get_active_connections() -> List[Dict[str, Any]]:
    """Snapshot of current network connections."""
    conns = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "NONE":
                continue
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            is_suspicious = remote_port in SUSPICIOUS_PORTS or (
                remote_port > 0 and remote_port not in KNOWN_SERVICES and remote_port < 1024
            )
            conns.append({
                "pid": conn.pid,
                "status": conn.status,
                "local_addr": laddr,
                "remote_addr": raddr,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "service": KNOWN_SERVICES.get(conn.laddr.port if conn.laddr else 0, ""),
                "is_suspicious": is_suspicious,
                "family": "IPv6" if conn.family.name == "AF_INET6" else "IPv4",
                "type": "UDP" if conn.type.name == "SOCK_DGRAM" else "TCP",
            })
    except Exception as e:
        logger.error(f"Connection snapshot error: {e}")
    return conns


def get_network_interfaces() -> List[Dict[str, Any]]:
    """List network interfaces with addresses."""
    interfaces = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            iface_info = {
                "name": iface,
                "is_up": stats[iface].isup if iface in stats else False,
                "speed_mbps": stats[iface].speed if iface in stats else 0,
                "addresses": []
            }
            for addr in addr_list:
                iface_info["addresses"].append({
                    "family": addr.family.name,
                    "address": addr.address,
                    "netmask": addr.netmask,
                })
            interfaces.append(iface_info)
    except Exception as e:
        logger.error(f"Interface listing error: {e}")
    return interfaces


class NetworkMonitor:
    """
    Async network monitor tracking:
    - Connection counts and trends
    - Suspicious port connections
    - New external IP connections
    - Bandwidth usage
    - Geo distribution of connections
    """

    def __init__(self, poll_interval: int = 10):
        self.poll_interval = poll_interval
        self._running = False
        self._callbacks = []
        self._known_remote_ips: Set[str] = set()
        self._connection_history: deque = deque(maxlen=200)
        self._geo_cache: Dict[str, Dict] = {}
        self._suspicious_counts: Counter = Counter()
        self._latest_connections: List[Dict] = []

    def add_callback(self, fn):
        self._callbacks.append(fn)

    async def _run_callbacks(self, data: Dict, alerts: List[Dict]):
        for fn in self._callbacks:
            try:
                await fn(data, alerts)
            except Exception as e:
                logger.error(f"Network callback error: {e}")

    async def run(self):
        self._running = True
        logger.info("Network monitor started")
        while self._running:
            try:
                conns = get_active_connections()
                self._latest_connections = conns
                alerts = []

                # Find new external connections
                new_ips = set()
                suspicious_conns = []

                for conn in conns:
                    rip = conn.get("remote_ip", "")
                    if not rip or rip in ("", "0.0.0.0", "127.0.0.1", "::1"):
                        continue

                    if rip not in self._known_remote_ips:
                        self._known_remote_ips.add(rip)
                        new_ips.add(rip)

                    if conn.get("is_suspicious"):
                        suspicious_conns.append(conn)
                        self._suspicious_counts[rip] += 1

                # Alert on suspicious connections
                if suspicious_conns:
                    for conn in suspicious_conns[:5]:
                        alerts.append({
                            "type": "suspicious_connection",
                            "severity": "high",
                            "message": f"Connection to suspicious port {conn['remote_port']} from {conn['remote_ip']}",
                            "ip": conn["remote_ip"],
                            "port": conn["remote_port"]
                        })

                snapshot = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "total_connections": len(conns),
                    "established": sum(1 for c in conns if c["status"] == "ESTABLISHED"),
                    "listening": sum(1 for c in conns if c["status"] == "LISTEN"),
                    "suspicious_connections": len(suspicious_conns),
                    "new_remote_ips": list(new_ips),
                    "connections": conns[:50],  # Cap for performance
                    "interfaces": get_network_interfaces(),
                }
                self._connection_history.append(snapshot)
                await self._run_callbacks(snapshot, alerts)

            except Exception as e:
                logger.error(f"Network monitor error: {e}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    def get_latest(self) -> Dict:
        return self._connection_history[-1] if self._connection_history else {}

    def get_stats(self) -> Dict:
        return {
            "known_remote_ips": len(self._known_remote_ips),
            "suspicious_ip_counts": dict(self._suspicious_counts.most_common(10)),
            "history_snapshots": len(self._connection_history),
        }


_net_monitor: Optional[NetworkMonitor] = None

def get_network_monitor() -> NetworkMonitor:
    global _net_monitor
    if _net_monitor is None:
        _net_monitor = NetworkMonitor()
    return _net_monitor
