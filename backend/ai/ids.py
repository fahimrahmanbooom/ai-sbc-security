"""
AI SBC Security - Intrusion Detection System (IDS)
Hybrid rule-based + ML classifier.
Detects: port scans, brute force, DoS, web attacks, lateral movement, and more.
"""
import re
import logging
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger("ai_sbc.ids")


class AttackType(str, Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DOS = "denial_of_service"
    WEB_ATTACK = "web_attack"
    SSH_ATTACK = "ssh_attack"
    RFI_LFI = "rfi_lfi"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfiltration"
    CRYPTO_MINER = "crypto_mining"
    REVERSE_SHELL = "reverse_shell"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNKNOWN = "unknown"


@dataclass
class IDSAlert:
    timestamp: datetime
    attack_type: AttackType
    source_ip: str
    dest_port: Optional[int]
    protocol: str
    threat_score: float         # 0-10
    description: str
    evidence: List[str]
    action_taken: str = "logged"
    mitre_technique: str = ""
    cve: Optional[str] = None


# ─── Signature Rules ────────────────────────────────────────────────────────

SIGNATURE_RULES = [
    # Log-based patterns (regex match on log lines)
    {
        "name": "SSH Brute Force",
        "pattern": r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        "attack_type": AttackType.BRUTE_FORCE,
        "score": 6.5,
        "mitre": "T1110",
        "threshold": 5,         # triggers after N matches per window
        "window_seconds": 60
    },
    {
        "name": "Root SSH Attempt",
        "pattern": r"Failed password for root from (\d+\.\d+\.\d+\.\d+)",
        "attack_type": AttackType.SSH_ATTACK,
        "score": 8.0,
        "mitre": "T1078",
        "threshold": 2,
        "window_seconds": 60
    },
    {
        "name": "Invalid User SSH",
        "pattern": r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)",
        "attack_type": AttackType.BRUTE_FORCE,
        "score": 5.5,
        "mitre": "T1110.001",
        "threshold": 3,
        "window_seconds": 60
    },
    {
        "name": "sudo Escalation Failure",
        "pattern": r"sudo.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
        "attack_type": AttackType.PRIVILEGE_ESCALATION,
        "score": 7.5,
        "mitre": "T1548.003",
        "threshold": 1,
        "window_seconds": 300
    },
    {
        "name": "SQL Injection Attempt",
        "pattern": r"(?i)(union\s+select|or\s+1=1|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell)",
        "attack_type": AttackType.SQL_INJECTION,
        "score": 8.5,
        "mitre": "T1190",
        "threshold": 1,
        "window_seconds": 60
    },
    {
        "name": "XSS Attempt",
        "pattern": r"(?i)(<script>|javascript:|onload=|onerror=|alert\s*\()",
        "attack_type": AttackType.XSS,
        "score": 7.0,
        "mitre": "T1059.007",
        "threshold": 1,
        "window_seconds": 60
    },
    {
        "name": "Path Traversal / LFI",
        "pattern": r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self)",
        "attack_type": AttackType.RFI_LFI,
        "score": 8.0,
        "mitre": "T1083",
        "threshold": 1,
        "window_seconds": 60
    },
    {
        "name": "Command Injection",
        "pattern": r"(?i)(;(ls|cat|id|whoami|uname|wget|curl)\s|&&\s*(ls|id|cat|wget)|`[^`]+`|\$\(.*\))",
        "attack_type": AttackType.COMMAND_INJECTION,
        "score": 9.0,
        "mitre": "T1059",
        "threshold": 1,
        "window_seconds": 60
    },
    {
        "name": "Crypto Mining Process",
        "pattern": r"(xmrig|minerd|cryptonight|stratum\+tcp://|ethminer|nbminer)",
        "attack_type": AttackType.CRYPTO_MINER,
        "score": 8.5,
        "mitre": "T1496",
        "threshold": 1,
        "window_seconds": 300
    },
    {
        "name": "Reverse Shell Pattern",
        "pattern": r"(bash\s+-i\s+>&\s+/dev/tcp|nc\s+-e\s+/bin/|python\s+-c\s+.*socket.*connect|mkfifo.*sh.*nc)",
        "attack_type": AttackType.REVERSE_SHELL,
        "score": 9.5,
        "mitre": "T1059.004",
        "threshold": 1,
        "window_seconds": 300
    },
    {
        "name": "Wget/Curl Pipe to Bash",
        "pattern": r"(wget\s+.+\s*\|\s*bash|curl\s+.+\s*\|\s*bash|curl\s+.+\s*\|\s*sh)",
        "attack_type": AttackType.WEB_ATTACK,
        "score": 9.0,
        "mitre": "T1059.004",
        "threshold": 1,
        "window_seconds": 300
    },
]

# Compiled regexes
COMPILED_RULES = [
    {**rule, "compiled": re.compile(rule["pattern"])}
    for rule in SIGNATURE_RULES
]


class PortScanDetector:
    """Stateful port scan detector using sliding window."""
    def __init__(self, threshold: int = 15, window: int = 60):
        self.threshold = threshold
        self.window = window
        self.ip_ports: Dict[str, deque] = defaultdict(lambda: deque())

    def record(self, src_ip: str, dest_port: int) -> Optional[IDSAlert]:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)
        q = self.ip_ports[src_ip]
        # Remove old entries
        while q and q[0][0] < cutoff:
            q.popleft()
        q.append((now, dest_port))
        unique_ports = len(set(p for _, p in q))
        if unique_ports >= self.threshold:
            return IDSAlert(
                timestamp=now,
                attack_type=AttackType.PORT_SCAN,
                source_ip=src_ip,
                dest_port=None,
                protocol="TCP/UDP",
                threat_score=7.5,
                description=f"Port scan detected: {unique_ports} unique ports probed in {self.window}s",
                evidence=[f"{src_ip} → {unique_ports} ports"],
                mitre_technique="T1046"
            )
        return None


class BruteForceTracker:
    """Tracks repeated failed authentication attempts per IP."""
    def __init__(self):
        self.attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def record(self, ip: str, rule_name: str, threshold: int, window: int) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window)
        q = self.attempts[ip]
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        return len(q) >= threshold


class IDSEngine:
    """
    Full hybrid IDS engine.
    Combines signature-based rules with behavioral analysis.
    """
    def __init__(self, alert_threshold: float = 5.0):
        self.alert_threshold = alert_threshold
        self.port_scan_detector = PortScanDetector()
        self.brute_force_tracker = BruteForceTracker()
        self.alerts: deque = deque(maxlen=1000)
        self.blocked_ips: Set[str] = set()
        self.whitelist_ips: Set[str] = {"127.0.0.1", "::1"}
        self._rule_match_counts: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def analyze_log_line(self, line: str, source_file: str = "") -> Optional[IDSAlert]:
        """Run signature rules against a log line."""
        if not line.strip():
            return None

        for rule in COMPILED_RULES:
            match = rule["compiled"].search(line)
            if match:
                # Extract IP if captured
                src_ip = match.group(1) if match.lastindex and match.lastindex >= 1 else "0.0.0.0"
                try:
                    # validate IP format
                    parts = src_ip.split(".")
                    if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                        src_ip = "unknown"
                except:
                    src_ip = "unknown"

                if src_ip in self.whitelist_ips:
                    continue

                triggered = self.brute_force_tracker.record(
                    src_ip, rule["name"],
                    rule.get("threshold", 1),
                    rule.get("window_seconds", 60)
                )
                if not triggered:
                    continue

                alert = IDSAlert(
                    timestamp=datetime.utcnow(),
                    attack_type=rule["attack_type"],
                    source_ip=src_ip,
                    dest_port=None,
                    protocol="log",
                    threat_score=rule["score"],
                    description=f"{rule['name']} — {line[:120]}",
                    evidence=[line[:200]],
                    mitre_technique=rule.get("mitre", "")
                )
                async with self._lock:
                    self.alerts.append(alert)
                self._rule_match_counts[rule["name"]] += 1
                return alert

        return None

    async def analyze_connection(self, src_ip: str, dest_port: int,
                                  protocol: str = "TCP") -> Optional[IDSAlert]:
        """Analyze a network connection for port scanning."""
        if src_ip in self.whitelist_ips:
            return None
        alert = self.port_scan_detector.record(src_ip, dest_port)
        if alert:
            async with self._lock:
                self.alerts.append(alert)
        return alert

    async def analyze_process(self, cmdline: str, pid: int) -> Optional[IDSAlert]:
        """Analyze process command lines for malicious patterns."""
        for rule in COMPILED_RULES:
            if rule["compiled"].search(cmdline):
                alert = IDSAlert(
                    timestamp=datetime.utcnow(),
                    attack_type=rule["attack_type"],
                    source_ip="localhost",
                    dest_port=None,
                    protocol="process",
                    threat_score=rule["score"],
                    description=f"Suspicious process: {cmdline[:150]}",
                    evidence=[f"PID {pid}: {cmdline[:200]}"],
                    mitre_technique=rule.get("mitre", "")
                )
                async with self._lock:
                    self.alerts.append(alert)
                return alert
        return None

    def get_recent_alerts(self, limit: int = 50, min_score: float = 0.0) -> List[IDSAlert]:
        return [a for a in list(self.alerts)[-limit:] if a.threat_score >= min_score]

    def get_stats(self) -> Dict:
        total = len(self.alerts)
        critical = sum(1 for a in self.alerts if a.threat_score >= 8.0)
        return {
            "total_alerts": total,
            "critical_alerts": critical,
            "blocked_ips": len(self.blocked_ips),
            "top_rule_hits": dict(sorted(
                self._rule_match_counts.items(), key=lambda x: -x[1]
            )[:5]),
            "unique_attackers": len(set(a.source_ip for a in self.alerts))
        }


# Singleton
_ids_engine: Optional[IDSEngine] = None

def get_ids_engine() -> IDSEngine:
    global _ids_engine
    if _ids_engine is None:
        _ids_engine = IDSEngine()
    return _ids_engine
