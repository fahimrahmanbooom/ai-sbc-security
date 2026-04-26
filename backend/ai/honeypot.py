"""
AI Honeypot — Low-interaction deception system
Listens on common attacker-targeted ports, captures probe details, clusters
attack fingerprints using ML, and feeds high-confidence attack signatures
back into the IDS engine for real-time blocking.
"""

import asyncio
import json
import logging
import os
import socket
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

HONEYPOT_DATA_DIR = "/var/lib/ai-sbc-security/honeypot"

# Ports the honeypot will emulate
# Key: port, Value: (service_name, banner_template)
HONEYPOT_PORTS: Dict[int, Tuple[str, bytes]] = {
    2222:  ("fake-ssh",   b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"),
    8080:  ("fake-http",  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\nContent-Length: 0\r\n\r\n"),
    2323:  ("fake-telnet", b"\xff\xfd\x18\xff\xfd\x1f\xff\xfd!\xff\xfd\"\xff\xfd'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x03"),
    3389:  ("fake-rdp",   b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"),
    1433:  ("fake-mssql", b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x1f\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x04\x04\x00\x26\x00\x01\xff"),
    3306:  ("fake-mysql", b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x32\x00"),
    6379:  ("fake-redis", b"+PONG\r\n"),
    5900:  ("fake-vnc",   b"RFB 003.008\n"),
    21:    ("fake-ftp",   b"220 ProFTPD 1.3.8 Server (ProFTPD) [127.0.0.1]\r\n"),
    23:    ("fake-telnet2", b"\xff\xfd\x01\xff\xfd\x1f"),
}


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class HoneypotProbe:
    src_ip: str
    src_port: int
    honeypot_port: int
    service: str
    payload: bytes
    payload_preview: str
    timestamp: float = field(default_factory=time.time)
    cluster_id: int = -1
    threat_label: str = "unknown"
    threat_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "honeypot_port": self.honeypot_port,
            "service": self.service,
            "payload_preview": self.payload_preview,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "cluster_id": self.cluster_id,
            "threat_label": self.threat_label,
            "threat_score": self.threat_score,
        }


@dataclass
class AttackCluster:
    cluster_id: int
    label: str              # "credential_brute_force" | "port_scan" | "exploit_attempt" | "recon" | "other"
    probe_count: int
    unique_ips: int
    first_seen: float
    last_seen: float
    top_ports: List[int]
    top_ips: List[str]
    description: str

    def to_dict(self) -> dict:
        return asdict(self)


# ── Payload classifier ─────────────────────────────────────────────────────────
class PayloadClassifier:
    """
    Classifies honeypot probe payloads into attack categories using
    heuristic pattern matching + lightweight feature-based scoring.
    """

    PATTERNS = {
        "credential_brute_force": [
            b"USER ", b"PASS ", b"AUTH ", b"LOGIN",
            b"admin", b"root", b"password", b"123456",
            b"\x00root\x00", b"SSH-",
        ],
        "exploit_attempt": [
            b"/../", b"../etc/passwd", b"cmd.exe", b"/bin/sh",
            b"eval(", b"exec(", b"system(", b"passthru(",
            b"\x90\x90\x90\x90",  # NOP sled
            b"SELECT ", b"UNION ", b"DROP TABLE",
            b"<script>", b"<?php",
            b"/etc/shadow", b"wget http", b"curl http",
        ],
        "recon": [
            b"HEAD /", b"OPTIONS *", b"HELP\r\n", b"VERSION\r\n",
            b"INFO\r\n", b"PING\r\n", b"\x00\x00\x00",
        ],
        "port_scan": [],  # detected by behavior, not payload
    }

    def classify(self, payload: bytes, service: str, src_ip: str, history: List["HoneypotProbe"]) -> Tuple[str, float]:
        if not payload:
            # Empty payload on connect = likely port scan
            return "port_scan", 0.4

        payload_lower = payload.lower()
        scores = defaultdict(float)

        for category, patterns in self.PATTERNS.items():
            for p in patterns:
                if p.lower() in payload_lower:
                    scores[category] += 1.0

        # Behavioral: multiple probes from same IP = brute force
        if history:
            same_ip_count = sum(1 for h in history[-50:] if h.src_ip == src_ip)
            if same_ip_count > 3:
                scores["credential_brute_force"] += same_ip_count * 0.5
            if same_ip_count > 10:
                scores["credential_brute_force"] += 5.0

        # Service-specific hints
        if "ssh" in service and scores["credential_brute_force"] > 0:
            scores["credential_brute_force"] *= 1.5
        if "mysql" in service or "mssql" in service:
            if scores["exploit_attempt"] > 0:
                scores["exploit_attempt"] *= 1.3

        if not any(scores.values()):
            return "other", 0.2

        best = max(scores, key=lambda k: scores[k])
        # Normalize score to 0-1
        raw_score = scores[best]
        normalized = min(1.0, raw_score / 10.0)
        # Map to threat score
        threat_score = 0.3 + 0.7 * normalized

        return best, round(threat_score, 3)


# ── Fingerprint clusterer ──────────────────────────────────────────────────────
class FingerprintClusterer:
    """
    Groups probes into behavioral clusters using simple feature distance.
    Maintains up to 20 active clusters; promotes high-confidence ones to IDS.
    """

    def __init__(self, max_clusters: int = 20):
        self._clusters: Dict[int, dict] = {}
        self._next_id = 0
        self._max = max_clusters

    def assign_cluster(self, probe: HoneypotProbe) -> int:
        """Assign probe to closest cluster or create new one."""
        if not self._clusters:
            return self._create_cluster(probe)

        best_id = -1
        best_score = -1

        for cid, cluster in self._clusters.items():
            # Score based on: same threat_label, port overlap, recent activity
            score = 0.0
            if cluster["label"] == probe.threat_label:
                score += 3.0
            if probe.honeypot_port in cluster["ports"]:
                score += 2.0
            # Recency bonus
            if (probe.timestamp - cluster["last_seen"]) < 300:
                score += 1.0
            # IP similarity (same /24)
                ip_net = ".".join(probe.src_ip.split(".")[:3])
                if any(h.startswith(ip_net) for h in cluster["ips"]):
                    score += 2.0

            if score > best_score:
                best_score = score
                best_id = cid

        if best_score >= 3.0:
            self._update_cluster(best_id, probe)
            return best_id

        if len(self._clusters) >= self._max:
            # Remove oldest cluster
            oldest = min(self._clusters, key=lambda k: self._clusters[k]["last_seen"])
            del self._clusters[oldest]

        return self._create_cluster(probe)

    def _create_cluster(self, probe: HoneypotProbe) -> int:
        cid = self._next_id
        self._next_id += 1
        self._clusters[cid] = {
            "count": 1,
            "label": probe.threat_label,
            "ports": {probe.honeypot_port},
            "ips": {probe.src_ip},
            "first_seen": probe.timestamp,
            "last_seen": probe.timestamp,
        }
        return cid

    def _update_cluster(self, cid: int, probe: HoneypotProbe):
        c = self._clusters[cid]
        c["count"] += 1
        c["ports"].add(probe.honeypot_port)
        c["ips"].add(probe.src_ip)
        c["last_seen"] = probe.timestamp

    def get_clusters(self) -> List[AttackCluster]:
        result = []
        for cid, c in sorted(self._clusters.items(), key=lambda x: -x[1]["count"]):
            ports = sorted(c["ports"])
            ips = list(c["ips"])
            desc = self._describe(c)
            result.append(AttackCluster(
                cluster_id=cid,
                label=c["label"],
                probe_count=c["count"],
                unique_ips=len(c["ips"]),
                first_seen=c["first_seen"],
                last_seen=c["last_seen"],
                top_ports=ports[:5],
                top_ips=ips[:5],
                description=desc,
            ))
        return result

    def _describe(self, cluster: dict) -> str:
        label = cluster["label"]
        count = cluster["count"]
        ips = len(cluster["ips"])
        ports = list(cluster["ports"])[:3]

        labels_text = {
            "credential_brute_force": f"Credential stuffing/brute-force: {count} attempts from {ips} IP(s) targeting ports {ports}",
            "exploit_attempt": f"Exploit attempts: {count} probes from {ips} IP(s) on ports {ports}",
            "recon": f"Reconnaissance sweep: {count} probes from {ips} IP(s) across ports {ports}",
            "port_scan": f"Port scanning: {count} silent connection attempts from {ips} IP(s)",
            "other": f"Unknown pattern: {count} probes from {ips} IP(s)",
        }
        return labels_text.get(label, f"{label}: {count} probes")


# ── TCP honeypot server ────────────────────────────────────────────────────────
class HoneypotServer:
    """
    Single-port low-interaction honeypot.
    Accepts connections, sends a fake banner, reads up to 2KB payload, logs and closes.
    """

    def __init__(self, port: int, service: str, banner: bytes, on_probe):
        self.port = port
        self.service = service
        self.banner = banner
        self.on_probe = on_probe
        self._server = None

    async def start(self):
        try:
            self._server = await asyncio.start_server(
                self._handle, "0.0.0.0", self.port,
                reuse_address=True,
            )
            logger.info("Honeypot listening on port %d (%s)", self.port, self.service)
        except OSError as e:
            logger.warning("Honeypot port %d unavailable: %s", self.port, e)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = peer[0], peer[1]

        try:
            # Send banner
            writer.write(self.banner)
            await writer.drain()

            # Read payload with short timeout
            try:
                payload = await asyncio.wait_for(reader.read(2048), timeout=5.0)
            except asyncio.TimeoutError:
                payload = b""

            await self.on_probe(src_ip, src_port, self.port, self.service, payload)

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ── Main honeypot engine ───────────────────────────────────────────────────────
class HoneypotEngine:
    def __init__(self, enabled_ports: Optional[List[int]] = None):
        self._ports = enabled_ports or list(HONEYPOT_PORTS.keys())
        self._servers: List[HoneypotServer] = []
        self._probes: deque = deque(maxlen=2000)
        self._classifier = PayloadClassifier()
        self._clusterer = FingerprintClusterer()
        self._ids_callbacks: List[Callable] = []
        self._alert_callbacks: List[Callable] = []
        self._running = False
        self._stats = {
            "total_probes": 0,
            "unique_ips": set(),
            "by_service": defaultdict(int),
            "started_at": None,
        }

    def on_ids_event(self, callback: Callable):
        """Register callback to receive high-confidence attack events for IDS."""
        self._ids_callbacks.append(callback)

    def on_alert(self, callback: Callable):
        """Register callback to receive honeypot alerts."""
        self._alert_callbacks.append(callback)

    async def start(self):
        self._running = True
        self._stats["started_at"] = datetime.now(tz=timezone.utc).isoformat()
        os.makedirs(HONEYPOT_DATA_DIR, exist_ok=True)

        for port in self._ports:
            if port not in HONEYPOT_PORTS:
                continue
            service, banner = HONEYPOT_PORTS[port]
            srv = HoneypotServer(port, service, banner, self._on_probe)
            await srv.start()
            self._servers.append(srv)

        logger.info("Honeypot engine started on %d ports", len(self._servers))

    async def stop(self):
        self._running = False
        for srv in self._servers:
            await srv.stop()

    async def _on_probe(
        self, src_ip: str, src_port: int,
        honeypot_port: int, service: str, payload: bytes
    ):
        # Skip private IPs (loopback / RFC1918) unless in debug mode
        if src_ip.startswith(("127.", "10.", "192.168.", "172.")):
            return

        payload_preview = payload[:128].decode("latin-1", errors="replace").replace("\n", "\\n").replace("\r", "\\r")

        probe = HoneypotProbe(
            src_ip=src_ip,
            src_port=src_port,
            honeypot_port=honeypot_port,
            service=service,
            payload=payload,
            payload_preview=payload_preview,
        )

        # Classify payload
        history = list(self._probes)
        label, score = self._classifier.classify(payload, service, src_ip, history)
        probe.threat_label = label
        probe.threat_score = score

        # Cluster
        cluster_id = self._clusterer.assign_cluster(probe)
        probe.cluster_id = cluster_id

        self._probes.append(probe)
        self._stats["total_probes"] += 1
        self._stats["unique_ips"].add(src_ip)
        self._stats["by_service"][service] += 1

        logger.debug(
            "Honeypot probe: %s:%d → port %d (%s) label=%s score=%.2f",
            src_ip, src_port, honeypot_port, service, label, score,
        )

        # Fire alert callbacks for high-threat probes
        if score >= 0.6:
            for cb in self._alert_callbacks:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(probe)
                    else:
                        cb(probe)
                except Exception as e:
                    logger.error("Honeypot alert callback error: %s", e)

        # Feed IDS for exploit attempts and high-confidence brute force
        if label in ("exploit_attempt", "credential_brute_force") and score >= 0.7:
            for cb in self._ids_callbacks:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(probe)
                    else:
                        cb(probe)
                except Exception as e:
                    logger.error("Honeypot IDS callback error: %s", e)

    def get_stats(self) -> dict:
        return {
            "total_probes": self._stats["total_probes"],
            "unique_ips": len(self._stats["unique_ips"]),
            "by_service": dict(self._stats["by_service"]),
            "active_ports": len(self._servers),
            "started_at": self._stats["started_at"],
            "clusters": len(self._clusterer._clusters),
        }

    def get_recent_probes(self, limit: int = 50) -> List[dict]:
        return [p.to_dict() for p in list(self._probes)[-limit:]]

    def get_clusters(self) -> List[dict]:
        return [c.to_dict() for c in self._clusterer.get_clusters()]

    def get_top_attackers(self, limit: int = 10) -> List[dict]:
        ip_count: Dict[str, dict] = defaultdict(lambda: {"count": 0, "services": set(), "max_score": 0.0, "last_seen": 0.0})
        for p in self._probes:
            entry = ip_count[p.src_ip]
            entry["count"] += 1
            entry["services"].add(p.service)
            entry["max_score"] = max(entry["max_score"], p.threat_score)
            entry["last_seen"] = max(entry["last_seen"], p.timestamp)

        sorted_ips = sorted(ip_count.items(), key=lambda x: -x[1]["count"])
        return [
            {
                "ip": ip,
                "probe_count": data["count"],
                "services_targeted": list(data["services"]),
                "max_threat_score": round(data["max_score"], 3),
                "last_seen_iso": datetime.fromtimestamp(
                    data["last_seen"], tz=timezone.utc
                ).isoformat() if data["last_seen"] else "",
            }
            for ip, data in sorted_ips[:limit]
        ]


# ── Singleton ──────────────────────────────────────────────────────────────────
_honeypot_instance: Optional[HoneypotEngine] = None

def get_honeypot() -> HoneypotEngine:
    global _honeypot_instance
    if _honeypot_instance is None:
        _honeypot_instance = HoneypotEngine()
    return _honeypot_instance
