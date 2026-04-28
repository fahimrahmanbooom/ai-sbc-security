"""
AI SBC Security - Log Intelligence Engine
AI-powered log parsing, correlation, threat scoring, and insight generation.
Supports: auth.log, syslog, kern.log, nginx, apache, fail2ban, and more.
"""
import re
import logging
import asyncio
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from ..utils.time import utcnow

logger = logging.getLogger("ai_sbc.log_intel")


class LogSource(str, Enum):
    AUTH = "auth"
    SYSLOG = "syslog"
    KERNEL = "kernel"
    NGINX = "nginx"
    APACHE = "apache"
    FAIL2BAN = "fail2ban"
    DOCKER = "docker"
    CRON = "cron"
    UNKNOWN = "unknown"


@dataclass
class ParsedLogEntry:
    raw: str
    timestamp: Optional[datetime]
    source: LogSource
    level: str          # debug, info, warning, error, critical
    process: str
    message: str
    ip: Optional[str]
    user: Optional[str]
    threat_indicators: List[str]
    threat_score: float


@dataclass
class LogInsight:
    generated_at: datetime
    title: str
    description: str
    severity: str
    affected_ips: List[str]
    affected_users: List[str]
    event_count: int
    timespan_minutes: int
    recommendations: List[str]


# ─── Log Parsers ─────────────────────────────────────────────────────────────

LOG_PATTERNS = {
    LogSource.AUTH: [
        re.compile(
            r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+(\S+)(?:\[\d+\])?: (.+)$"
        ),
    ],
    LogSource.NGINX: [
        re.compile(
            r'^(\d+\.\d+\.\d+\.\d+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'
        ),
    ],
    LogSource.APACHE: [
        re.compile(
            r'^(\d+\.\d+\.\d+\.\d+) \S+ (\S+) \[([^\]]+)\] "([^"]+)" (\d+) (\S+)'
        ),
    ],
}

THREAT_KEYWORDS = {
    "critical": [
        "reverse shell", "rootkit", "privilege escalation",
        "exploit", "0day", "zero day", "kernel panic", "oom killer",
        "cryptominer", "xmrig", "minerd"
    ],
    "high": [
        "authentication failure", "failed password", "invalid user",
        "segfault", "buffer overflow", "injection", "xss", "csrf",
        "sudo failed", "permission denied", "access denied"
    ],
    "medium": [
        "port scan", "connection refused", "timeout", "error",
        "warning", "fail2ban", "banned", "blocked", "rejected"
    ],
    "low": [
        "login", "logout", "session", "disconnect", "connect"
    ]
}

IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_PATTERN = re.compile(r"(?:user|for|username)\s+(\w+)", re.IGNORECASE)
TIMESTAMP_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
    (re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    (re.compile(r"(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
]


def detect_log_source(filepath: str) -> LogSource:
    fp = filepath.lower()
    if "auth" in fp: return LogSource.AUTH
    if "syslog" in fp: return LogSource.SYSLOG
    if "kern" in fp: return LogSource.KERNEL
    if "nginx" in fp: return LogSource.NGINX
    if "apache" in fp or "httpd" in fp: return LogSource.APACHE
    if "fail2ban" in fp: return LogSource.FAIL2BAN
    if "docker" in fp: return LogSource.DOCKER
    if "cron" in fp: return LogSource.CRON
    return LogSource.UNKNOWN


def parse_timestamp(line: str) -> Optional[datetime]:
    now = utcnow()
    for pattern, fmt in TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if m:
            try:
                ts = datetime.strptime(m.group(1), fmt)
                if ts.year == 1900:
                    ts = ts.replace(year=now.year)
                return ts
            except:
                continue
    return None


def calculate_threat_score(line: str, indicators: List[str]) -> float:
    score = 0.0
    line_lower = line.lower()
    for level, keywords in THREAT_KEYWORDS.items():
        weight = {"critical": 0.9, "high": 0.6, "medium": 0.35, "low": 0.1}[level]
        for kw in keywords:
            if kw in line_lower:
                score = max(score, weight)
                indicators.append(kw)
    return round(min(1.0, score), 3)


def parse_log_line(line: str, source: LogSource) -> ParsedLogEntry:
    timestamp = parse_timestamp(line)
    indicators = []
    threat_score = calculate_threat_score(line, indicators)
    ips = IP_PATTERN.findall(line)
    users = USER_PATTERN.findall(line)
    ip = ips[0] if ips else None
    user = users[0] if users else None

    # Determine severity level
    line_lower = line.lower()
    if any(k in line_lower for k in ["emerg", "crit", "alert"]): level = "critical"
    elif any(k in line_lower for k in ["error", "err", "failed", "failure"]): level = "error"
    elif any(k in line_lower for k in ["warn", "warning"]): level = "warning"
    elif any(k in line_lower for k in ["notice", "info"]): level = "info"
    else: level = "debug"

    # Extract process name
    proc_match = re.search(r"\s(\w+(?:d|\[\d+\])?)\s*:", line)
    process = proc_match.group(1) if proc_match else "unknown"

    return ParsedLogEntry(
        raw=line[:500],
        timestamp=timestamp,
        source=source,
        level=level,
        process=process,
        message=line[:300],
        ip=ip,
        user=user,
        threat_indicators=list(set(indicators)),
        threat_score=threat_score
    )


class CorrelationEngine:
    """
    Correlates events across log sources to detect attack chains
    and coordinated threats within a time window.
    """
    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self.events_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.events_by_user: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.recent_events: deque = deque(maxlen=5000)

    def add_event(self, entry: ParsedLogEntry):
        now = utcnow()
        if entry.ip:
            self.events_by_ip[entry.ip].append(entry)
        if entry.user:
            self.events_by_user[entry.user].append(entry)
        self.recent_events.append(entry)

    def _get_window_events(self, events: deque) -> List[ParsedLogEntry]:
        cutoff = utcnow() - timedelta(seconds=self.window)
        return [e for e in events if e.timestamp and e.timestamp > cutoff]

    def correlate(self) -> List[LogInsight]:
        insights = []
        now = utcnow()

        # Pattern 1: IP with multiple high-severity events
        for ip, events in self.events_by_ip.items():
            window_evts = self._get_window_events(events)
            high_sev = [e for e in window_evts if e.threat_score >= 0.5]
            if len(high_sev) >= 3:
                insights.append(LogInsight(
                    generated_at=now,
                    title=f"Sustained attack from {ip}",
                    description=f"IP {ip} generated {len(high_sev)} high-severity events in {self.window//60} minutes",
                    severity="high",
                    affected_ips=[ip],
                    affected_users=list(set(e.user for e in high_sev if e.user)),
                    event_count=len(high_sev),
                    timespan_minutes=self.window // 60,
                    recommendations=[
                        f"Block IP {ip} with: sudo iptables -A INPUT -s {ip} -j DROP",
                        "Review all recent authentication logs",
                        "Check for unauthorized changes to system files"
                    ]
                ))

        # Pattern 2: Multiple users failing auth from same IP (credential stuffing)
        for ip, events in self.events_by_ip.items():
            window_evts = self._get_window_events(events)
            auth_fails = [e for e in window_evts
                          if "failed password" in e.raw.lower() or "invalid user" in e.raw.lower()]
            unique_users = set(e.user for e in auth_fails if e.user)
            if len(unique_users) >= 3 and len(auth_fails) >= 5:
                insights.append(LogInsight(
                    generated_at=now,
                    title=f"Credential stuffing from {ip}",
                    description=(f"IP {ip} attempted auth for {len(unique_users)} different users "
                                 f"({len(auth_fails)} failures in {self.window//60}min)"),
                    severity="critical",
                    affected_ips=[ip],
                    affected_users=list(unique_users),
                    event_count=len(auth_fails),
                    timespan_minutes=self.window // 60,
                    recommendations=[
                        f"Immediately block {ip}",
                        "Enable fail2ban if not already active",
                        "Audit all user accounts for unauthorized access"
                    ]
                ))

        # Pattern 3: Same user failing from multiple IPs (account targeted)
        for user, events in self.events_by_user.items():
            window_evts = self._get_window_events(events)
            auth_fails = [e for e in window_evts if e.threat_score >= 0.4]
            unique_ips = set(e.ip for e in auth_fails if e.ip)
            if len(unique_ips) >= 3:
                insights.append(LogInsight(
                    generated_at=now,
                    title=f"User '{user}' targeted from {len(unique_ips)} IPs",
                    description=f"Account '{user}' is being targeted in a distributed attack",
                    severity="high",
                    affected_ips=list(unique_ips),
                    affected_users=[user],
                    event_count=len(auth_fails),
                    timespan_minutes=self.window // 60,
                    recommendations=[
                        f"Force password reset for user '{user}'",
                        "Enforce MFA on this account",
                        "Consider temporarily disabling the account"
                    ]
                ))

        return insights


class LogIntelEngine:
    """Master log intelligence engine — parsing, scoring, correlation, insights."""

    def __init__(self):
        self.correlation_engine = CorrelationEngine()
        self.parsed_count = 0
        self.threat_count = 0
        self.insights: deque = deque(maxlen=100)
        self.top_ips: Counter = Counter()
        self.top_users: Counter = Counter()
        self._lock = asyncio.Lock()

    async def process_line(self, line: str, filepath: str = "") -> ParsedLogEntry:
        source = detect_log_source(filepath)
        entry = parse_log_line(line, source)
        async with self._lock:
            self.parsed_count += 1
            if entry.threat_score >= 0.3:
                self.threat_count += 1
            if entry.ip:
                self.top_ips[entry.ip] += 1
            if entry.user:
                self.top_users[entry.user] += 1
        self.correlation_engine.add_event(entry)
        return entry

    async def run_correlation(self) -> List[LogInsight]:
        insights = self.correlation_engine.correlate()
        async with self._lock:
            for insight in insights:
                self.insights.appendleft(insight)
        return insights

    def get_stats(self) -> Dict:
        return {
            "total_parsed": self.parsed_count,
            "threat_events": self.threat_count,
            "threat_rate": round(self.threat_count / max(1, self.parsed_count), 4),
            "top_ips": dict(self.top_ips.most_common(10)),
            "top_users": dict(self.top_users.most_common(10)),
            "total_insights": len(self.insights),
        }

    def get_recent_insights(self, limit: int = 20) -> List[LogInsight]:
        return list(self.insights)[:limit]


# Singleton
_log_intel: Optional[LogIntelEngine] = None

def get_log_intel() -> LogIntelEngine:
    global _log_intel
    if _log_intel is None:
        _log_intel = LogIntelEngine()
    return _log_intel
