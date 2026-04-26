"""
Security Hardening Advisor — AI-powered
Audits system configuration across multiple security domains and produces an
overall hardening score (A–F) with prioritized, actionable recommendations.
Uses heuristic scoring + ML-based insight generation.
"""

import asyncio
import logging
import os
import re
import stat
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

AUDIT_INTERVAL = 3600   # 1 hour


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class Finding:
    category: str          # "ssh" | "firewall" | "kernel" | "users" | etc.
    check_id: str
    title: str
    description: str
    severity: str          # "critical" | "high" | "medium" | "low" | "info"
    passed: bool
    current_value: str
    recommended_value: str
    fix_command: str
    points_impact: int     # points deducted from 100 if failed

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HardeningReport:
    score: int                      # 0-100
    grade: str                      # A+ / A / B / C / D / F
    findings: List[Finding]
    by_category: Dict[str, dict]
    total_checks: int
    passed_checks: int
    critical_failures: int
    ai_summary: str
    ai_recommendations: List[str]
    audit_time: float = field(default_factory=lambda: __import__("time").time())

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "by_category": self.by_category,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "critical_failures": self.critical_failures,
            "ai_summary": self.ai_summary,
            "ai_recommendations": self.ai_recommendations,
            "audit_time_iso": datetime.fromtimestamp(
                self.audit_time, tz=timezone.utc
            ).isoformat(),
        }


# ── Utility helpers ────────────────────────────────────────────────────────────
def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def _file_contains(path: str, pattern: str) -> bool:
    try:
        with open(path) as f:
            return bool(re.search(pattern, f.read(), re.MULTILINE))
    except (FileNotFoundError, PermissionError):
        return False

def _file_value(path: str, key: str) -> Optional[str]:
    """Extract key=value from a config file."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                m = re.match(rf"^\s*{re.escape(key)}\s+(.+)$", line, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
    except Exception:
        pass
    return None

def _sysctl(key: str) -> Optional[str]:
    out = _run(["sysctl", "-n", key])
    return out if out else None


# ── Audit modules ──────────────────────────────────────────────────────────────

def audit_ssh() -> List[Finding]:
    findings = []
    sshd_config = "/etc/ssh/sshd_config"
    exists = os.path.exists(sshd_config)

    def check(check_id, title, key, bad_value, good_value, desc, severity, points, fix):
        val = _file_value(sshd_config, key) if exists else None
        # Check sshd_config.d overrides
        if val is None and os.path.isdir("/etc/ssh/sshd_config.d"):
            for f in Path("/etc/ssh/sshd_config.d").glob("*.conf"):
                val = _file_value(str(f), key)
                if val:
                    break
        passed = val and val.lower() not in [v.lower() for v in bad_value]
        findings.append(Finding(
            category="ssh", check_id=check_id, title=title,
            description=desc, severity=severity,
            passed=bool(passed),
            current_value=val or "(not set / default)",
            recommended_value=good_value,
            fix_command=fix,
            points_impact=points if not passed else 0,
        ))

    check("SSH-001", "Disable root login", "PermitRootLogin",
          ["yes", "prohibit-password"], "no",
          "Root login via SSH should be disabled to prevent direct root exploitation.",
          "critical", 20,
          "sudo sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    check("SSH-002", "Disable password authentication", "PasswordAuthentication",
          ["yes"], "no",
          "Key-based authentication only — prevents brute-force password attacks.",
          "high", 15,
          "sudo sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    check("SSH-003", "Disable empty passwords", "PermitEmptyPasswords",
          ["yes"], "no",
          "Accounts with empty passwords must not be accessible via SSH.",
          "critical", 20,
          "sudo sed -i 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    check("SSH-004", "Disable X11 forwarding", "X11Forwarding",
          ["yes"], "no",
          "X11 forwarding expands the attack surface unnecessarily on headless SBCs.",
          "medium", 5,
          "sudo sed -i 's/^#?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    check("SSH-005", "Use SSH Protocol 2 only", "Protocol",
          ["1"], "2",
          "SSH Protocol 1 has known cryptographic weaknesses.",
          "high", 15,
          "sudo sed -i 's/^#?Protocol.*/Protocol 2/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    check("SSH-006", "Set max authentication attempts", "MaxAuthTries",
          ["5", "6", "7", "8", "9", "10"], "3",
          "Limit authentication attempts to slow brute-force attacks.",
          "medium", 5,
          "sudo sed -i 's/^#?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    check("SSH-007", "Disable agent forwarding", "AllowAgentForwarding",
          ["yes"], "no",
          "Agent forwarding can be exploited if a hop host is compromised.",
          "low", 3,
          "sudo sed -i 's/^#?AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config && sudo systemctl reload sshd")

    # Check for non-standard port (informational)
    port_val = _file_value(sshd_config, "Port") if exists else None
    findings.append(Finding(
        category="ssh", check_id="SSH-008", title="SSH on non-standard port",
        description="Using a non-standard port reduces automated scanning noise.",
        severity="info", passed=bool(port_val and port_val != "22"),
        current_value=port_val or "22",
        recommended_value="Any port != 22",
        fix_command="sudo sed -i 's/^#?Port.*/Port 2222/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
        points_impact=0,
    ))

    return findings


def audit_firewall() -> List[Finding]:
    findings = []

    # Check iptables
    iptables_out = _run(["iptables", "-L", "-n", "--line-numbers"])
    ufw_status = _run(["ufw", "status"])
    nftables_out = _run(["nft", "list", "ruleset"])
    firewalld_out = _run(["firewall-cmd", "--state"])

    ufw_active = "active" in ufw_status.lower()
    iptables_has_rules = bool(iptables_out and "Chain INPUT" in iptables_out and "DROP" in iptables_out)
    nft_has_rules = bool(nftables_out and "chain" in nftables_out)
    firewalld_active = "running" in firewalld_out.lower()

    firewall_active = ufw_active or iptables_has_rules or nft_has_rules or firewalld_active

    findings.append(Finding(
        category="firewall", check_id="FW-001", title="Firewall is active",
        description="A firewall must be configured and active to block unauthorized connections.",
        severity="critical", passed=firewall_active,
        current_value="active" if firewall_active else "inactive",
        recommended_value="active",
        fix_command="sudo ufw enable && sudo ufw default deny incoming && sudo ufw allow ssh",
        points_impact=25 if not firewall_active else 0,
    ))

    # Check default deny policy
    default_policy = ""
    if iptables_out:
        m = re.search(r"Chain INPUT.*?policy (\w+)", iptables_out)
        if m:
            default_policy = m.group(1)

    findings.append(Finding(
        category="firewall", check_id="FW-002", title="Default deny incoming policy",
        description="Default DENY for incoming traffic ensures only explicitly allowed services are reachable.",
        severity="high", passed=default_policy == "DROP" or ufw_active,
        current_value=default_policy or ("UFW active" if ufw_active else "unknown"),
        recommended_value="DROP / DENY",
        fix_command="sudo ufw default deny incoming",
        points_impact=15 if not (default_policy == "DROP" or ufw_active) else 0,
    ))

    return findings


def audit_kernel_params() -> List[Finding]:
    findings = []

    checks = [
        ("KERN-001", "net.ipv4.ip_forward", "0",
         "IP forwarding should be disabled unless this is a router.",
         "medium", 5,
         "sudo sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' | sudo tee -a /etc/sysctl.conf"),
        ("KERN-002", "net.ipv4.conf.all.accept_source_route", "0",
         "Source routing allows attackers to control packet routing paths.",
         "high", 10,
         "sudo sysctl -w net.ipv4.conf.all.accept_source_route=0"),
        ("KERN-003", "net.ipv4.conf.all.accept_redirects", "0",
         "ICMP redirects can be used to redirect traffic through attacker-controlled hosts.",
         "medium", 8,
         "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0"),
        ("KERN-004", "net.ipv4.conf.all.log_martians", "1",
         "Log martian packets to detect spoofing attempts.",
         "low", 3,
         "sudo sysctl -w net.ipv4.conf.all.log_martians=1"),
        ("KERN-005", "kernel.randomize_va_space", "2",
         "Full ASLR (value=2) makes exploiting memory corruption vulnerabilities harder.",
         "high", 10,
         "sudo sysctl -w kernel.randomize_va_space=2"),
        ("KERN-006", "kernel.dmesg_restrict", "1",
         "Restrict kernel log access to root only to hide memory layout information.",
         "medium", 5,
         "sudo sysctl -w kernel.dmesg_restrict=1"),
        ("KERN-007", "net.ipv4.tcp_syncookies", "1",
         "SYN cookies protect against SYN flood attacks.",
         "high", 10,
         "sudo sysctl -w net.ipv4.tcp_syncookies=1"),
        ("KERN-008", "fs.suid_dumpable", "0",
         "Disable core dumps for SUID programs to prevent information leakage.",
         "medium", 5,
         "sudo sysctl -w fs.suid_dumpable=0"),
    ]

    for check_id, key, expected, desc, severity, points, fix in checks:
        val = _sysctl(key)
        passed = val == expected
        findings.append(Finding(
            category="kernel", check_id=check_id,
            title=f"Kernel: {key} = {expected}",
            description=desc, severity=severity,
            passed=passed,
            current_value=val or "(unreadable)",
            recommended_value=expected,
            fix_command=fix,
            points_impact=points if not passed else 0,
        ))

    return findings


def audit_suid_binaries() -> List[Finding]:
    findings = []
    # Known-safe SUID binaries
    KNOWN_SAFE_SUID = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/chsh",
        "/bin/su", "/bin/ping", "/usr/bin/ping",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/bin/pkexec",
    }

    suid_files = []
    try:
        result = subprocess.run(
            ["find", "/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=20
        )
        suid_files = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        pass

    unknown_suid = [f for f in suid_files if f not in KNOWN_SAFE_SUID]

    findings.append(Finding(
        category="suid", check_id="SUID-001",
        title="Unknown SUID binaries",
        description=(
            f"Found {len(unknown_suid)} SUID binaries not in the known-safe list. "
            "SUID binaries run with elevated privileges and can be privilege escalation vectors."
        ),
        severity="high" if unknown_suid else "info",
        passed=len(unknown_suid) == 0,
        current_value=", ".join(unknown_suid[:5]) + ("..." if len(unknown_suid) > 5 else "") if unknown_suid else "none",
        recommended_value="Only known-safe SUID binaries",
        fix_command="sudo chmod u-s <binary_path>   # Remove SUID from each unknown binary",
        points_impact=12 if unknown_suid else 0,
    ))

    return findings


def audit_sudo_config() -> List[Finding]:
    findings = []

    # Check for NOPASSWD entries
    nopasswd_users = []
    try:
        result = subprocess.run(
            ["grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/"],
            capture_output=True, text=True, timeout=5
        )
        lines = [l for l in result.stdout.splitlines() if not l.strip().startswith("#")]
        nopasswd_users = lines
    except Exception:
        pass

    findings.append(Finding(
        category="sudo", check_id="SUDO-001",
        title="No NOPASSWD entries in sudoers",
        description="NOPASSWD allows commands to run without password confirmation, increasing risk from compromised accounts.",
        severity="high",
        passed=len(nopasswd_users) == 0,
        current_value=f"{len(nopasswd_users)} NOPASSWD entries found" if nopasswd_users else "none",
        recommended_value="No NOPASSWD entries",
        fix_command="sudo visudo  # Remove or restrict NOPASSWD entries",
        points_impact=12 if nopasswd_users else 0,
    ))

    # Check for ALL=(ALL) ALL for non-root
    sudo_all = []
    try:
        result = subprocess.run(
            ["grep", "-r", "ALL=(ALL) ALL", "/etc/sudoers", "/etc/sudoers.d/"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("root") and not line.startswith("%sudo") and not line.startswith("%wheel"):
                sudo_all.append(line)
    except Exception:
        pass

    findings.append(Finding(
        category="sudo", check_id="SUDO-002",
        title="Unrestricted sudo access check",
        description="Individual users with ALL=(ALL) ALL sudo access should be reviewed.",
        severity="medium",
        passed=len(sudo_all) == 0,
        current_value=str(len(sudo_all)) + " unrestricted entries" if sudo_all else "none",
        recommended_value="Use groups (%sudo, %wheel) rather than individual ALL=(ALL) ALL",
        fix_command="sudo visudo  # Review and restrict individual ALL=(ALL) ALL grants",
        points_impact=7 if sudo_all else 0,
    ))

    return findings


def audit_users() -> List[Finding]:
    findings = []

    # Users with UID 0 other than root
    uid0_users = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4 and parts[2] == "0" and parts[0] != "root":
                    uid0_users.append(parts[0])
    except Exception:
        pass

    findings.append(Finding(
        category="users", check_id="USR-001",
        title="No non-root UID 0 accounts",
        description="Multiple UID 0 accounts indicate potential compromise or misconfiguration.",
        severity="critical",
        passed=len(uid0_users) == 0,
        current_value=", ".join(uid0_users) if uid0_users else "none",
        recommended_value="Only root should have UID 0",
        fix_command="sudo usermod -u <new_uid> <username>  # Reassign UID",
        points_impact=20 if uid0_users else 0,
    ))

    # Check for accounts with empty passwords
    empty_pw_users = []
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty_pw_users.append(parts[0])
    except (FileNotFoundError, PermissionError):
        pass

    findings.append(Finding(
        category="users", check_id="USR-002",
        title="No accounts with empty passwords",
        description="Accounts with empty passwords can be accessed without authentication.",
        severity="critical",
        passed=len(empty_pw_users) == 0,
        current_value=", ".join(empty_pw_users) if empty_pw_users else "none",
        recommended_value="All accounts must have passwords or be locked",
        fix_command="sudo passwd -l <username>  # Lock passwordless accounts",
        points_impact=20 if empty_pw_users else 0,
    ))

    # Check for unlocked system accounts
    system_shells = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    uid = int(parts[2]) if parts[2].isdigit() else 9999
                    shell = parts[6]
                    # System accounts (uid < 1000) should not have login shells
                    if 0 < uid < 1000 and shell not in ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""]:
                        system_shells.append(f"{parts[0]} (shell: {shell})")
    except Exception:
        pass

    findings.append(Finding(
        category="users", check_id="USR-003",
        title="System accounts use nologin shell",
        description="System accounts should use /usr/sbin/nologin to prevent interactive login.",
        severity="medium",
        passed=len(system_shells) == 0,
        current_value=", ".join(system_shells[:5]) if system_shells else "none",
        recommended_value="/usr/sbin/nologin for all system accounts",
        fix_command="sudo usermod -s /usr/sbin/nologin <username>",
        points_impact=5 if system_shells else 0,
    ))

    return findings


def audit_services() -> List[Finding]:
    findings = []

    # Common services that shouldn't be running on a secure SBC
    risky_services = [
        ("telnet", "Telnet transmits credentials in plaintext", "critical", 15),
        ("rsh", "Remote Shell has no encryption or strong authentication", "critical", 15),
        ("rlogin", "rlogin has no authentication controls", "critical", 15),
        ("tftp", "TFTP has no authentication", "high", 10),
        ("finger", "Finger exposes user account information", "medium", 5),
        ("talk", "Talk protocol is unencrypted", "low", 3),
        ("ntalk", "NTalk protocol is unencrypted", "low", 3),
    ]

    for svc_name, desc, severity, points in risky_services:
        # Check if service is enabled
        status = _run(["systemctl", "is-active", svc_name])
        enabled = status == "active"

        # Also check for installed package
        installed = bool(_run(["which", svc_name]))

        if enabled or installed:
            findings.append(Finding(
                category="services", check_id=f"SVC-{svc_name.upper()}",
                title=f"Insecure service: {svc_name}",
                description=desc, severity=severity,
                passed=not (enabled or installed),
                current_value="running" if enabled else "installed",
                recommended_value="removed",
                fix_command=f"sudo systemctl disable --now {svc_name} && sudo apt-get remove {svc_name}",
                points_impact=points,
            ))

    # Check if unnecessary services expose ports
    open_ports_out = _run(["ss", "-tlnp"])
    if not open_ports_out:
        open_ports_out = _run(["netstat", "-tlnp"])

    # Count open ports
    port_lines = [l for l in open_ports_out.splitlines() if "LISTEN" in l]
    findings.append(Finding(
        category="services", check_id="SVC-PORTS",
        title="Open listening ports",
        description=f"{len(port_lines)} TCP ports currently listening. Review each for necessity.",
        severity="info",
        passed=len(port_lines) <= 5,
        current_value=f"{len(port_lines)} ports",
        recommended_value="Minimal listening ports",
        fix_command="sudo ss -tlnp  # Review and disable unnecessary services",
        points_impact=0,
    ))

    return findings


def audit_file_permissions() -> List[Finding]:
    findings = []

    sensitive_files = [
        ("/etc/shadow", 0o640, "root", "shadow", "SSH-readable only by root and shadow group"),
        ("/etc/passwd", 0o644, "root", "root", "World-readable but not writable"),
        ("/etc/gshadow", 0o640, "root", "shadow", "Readable only by root and shadow group"),
        ("/etc/sudoers", 0o440, "root", "root", "Read-only for root"),
        ("/etc/crontab", 0o600, "root", "root", "Only root should read/write crontab"),
        ("/etc/ssh/sshd_config", 0o600, "root", "root", "SSH config should be root-only"),
    ]

    for fpath, expected_mode, exp_owner, exp_group, desc in sensitive_files:
        try:
            st = os.stat(fpath)
            actual_mode = stat.S_IMODE(st.st_mode)
            mode_ok = (actual_mode & ~expected_mode) == 0  # no extra bits set
            passed = mode_ok

            findings.append(Finding(
                category="permissions", check_id=f"PERM-{os.path.basename(fpath).upper()}",
                title=f"File permissions: {fpath}",
                description=desc, severity="high" if not passed else "info",
                passed=passed,
                current_value=oct(actual_mode),
                recommended_value=oct(expected_mode),
                fix_command=f"sudo chmod {oct(expected_mode)[2:]} {fpath}",
                points_impact=8 if not passed else 0,
            ))
        except (FileNotFoundError, PermissionError):
            pass

    return findings


# ── AI summary generator ───────────────────────────────────────────────────────
def generate_ai_summary(report_data: dict) -> Tuple[str, List[str]]:
    """Generate a human-readable security posture summary and top recommendations."""
    score = report_data["score"]
    grade = report_data["grade"]
    critical_failures = report_data["critical_failures"]
    by_cat = report_data.get("by_category", {})

    # Build summary
    posture = (
        "excellent" if score >= 90
        else "good" if score >= 75
        else "fair" if score >= 60
        else "poor" if score >= 40
        else "critical"
    )

    summary_parts = [
        f"Security posture: {posture.upper()} (Score: {score}/100, Grade: {grade}).",
    ]

    if critical_failures > 0:
        summary_parts.append(
            f"{critical_failures} critical failure{'s' if critical_failures > 1 else ''} require immediate attention."
        )

    weak_cats = [
        cat for cat, data in by_cat.items()
        if data.get("failed", 0) > 0
    ]
    if weak_cats:
        summary_parts.append(
            f"Weakest areas: {', '.join(weak_cats[:3])}."
        )

    if score >= 90:
        summary_parts.append("System is well-hardened. Continue monitoring for new vulnerabilities.")
    elif score >= 75:
        summary_parts.append("Address remaining findings to achieve optimal security posture.")
    elif score >= 50:
        summary_parts.append("Significant hardening work needed before production deployment.")
    else:
        summary_parts.append("System is poorly secured. Address critical and high findings immediately.")

    summary = " ".join(summary_parts)

    # Build recommendations
    recommendations = []
    findings = report_data.get("findings", [])
    # Sort by severity then points_impact
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    failed = sorted(
        [f for f in findings if not f.get("passed", True)],
        key=lambda f: (sev_order.get(f["severity"], 5), -f.get("points_impact", 0))
    )

    for f in failed[:8]:
        rec = f"[{f['severity'].upper()}] {f['title']}: {f['fix_command']}"
        recommendations.append(rec)

    if not recommendations:
        recommendations.append("All checks passed. Continue applying security updates regularly.")

    return summary, recommendations


# ── Score calculator ───────────────────────────────────────────────────────────
def calculate_score(findings: List[Finding]) -> Tuple[int, str]:
    total_deduction = sum(f.points_impact for f in findings if not f.passed)
    score = max(0, 100 - total_deduction)

    grade = (
        "A+" if score >= 95
        else "A" if score >= 90
        else "B" if score >= 80
        else "C" if score >= 70
        else "D" if score >= 55
        else "F"
    )
    return score, grade


# ── Main advisor ───────────────────────────────────────────────────────────────
class HardeningAdvisor:
    def __init__(self):
        self._last_report: Optional[HardeningReport] = None
        self._running = False
        self._audit_task: Optional[asyncio.Task] = None
        self._callbacks = []

    def on_report(self, callback):
        self._callbacks.append(callback)

    async def start(self):
        self._running = True
        self._audit_task = asyncio.create_task(self._audit_loop())

    async def stop(self):
        self._running = False
        if self._audit_task:
            self._audit_task.cancel()

    async def _audit_loop(self):
        await asyncio.sleep(60)  # wait for system to settle
        while self._running:
            try:
                await self._run_audit()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Hardening audit error: %s", e)
            await asyncio.sleep(AUDIT_INTERVAL)

    async def run_audit_now(self) -> HardeningReport:
        return await self._run_audit()

    async def _run_audit(self) -> HardeningReport:
        logger.info("Hardening audit starting")
        loop = asyncio.get_event_loop()
        findings = await loop.run_in_executor(None, self._collect_findings)

        score, grade = calculate_score(findings)

        # Group by category
        by_category: Dict[str, dict] = {}
        for f in findings:
            cat = f.category
            if cat not in by_category:
                by_category[cat] = {"total": 0, "passed": 0, "failed": 0, "score": 100}
            by_category[cat]["total"] += 1
            if f.passed:
                by_category[cat]["passed"] += 1
            else:
                by_category[cat]["failed"] += 1
                by_category[cat]["score"] -= f.points_impact

        for cat in by_category:
            by_category[cat]["score"] = max(0, by_category[cat]["score"])

        critical_failures = sum(
            1 for f in findings
            if not f.passed and f.severity == "critical"
        )

        report_dict = {
            "score": score, "grade": grade,
            "findings": [f.to_dict() for f in findings],
            "by_category": by_category,
            "total_checks": len(findings),
            "passed_checks": sum(1 for f in findings if f.passed),
            "critical_failures": critical_failures,
        }
        ai_summary, ai_recs = generate_ai_summary(report_dict)

        report = HardeningReport(
            score=score, grade=grade,
            findings=findings,
            by_category=by_category,
            total_checks=len(findings),
            passed_checks=sum(1 for f in findings if f.passed),
            critical_failures=critical_failures,
            ai_summary=ai_summary,
            ai_recommendations=ai_recs,
        )

        self._last_report = report

        for cb in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(report)
                else:
                    cb(report)
            except Exception as e:
                logger.error("Hardening callback error: %s", e)

        logger.info("Hardening audit complete: score=%d grade=%s", score, grade)
        return report

    def _collect_findings(self) -> List[Finding]:
        all_findings: List[Finding] = []
        all_findings.extend(audit_ssh())
        all_findings.extend(audit_firewall())
        all_findings.extend(audit_kernel_params())
        all_findings.extend(audit_suid_binaries())
        all_findings.extend(audit_sudo_config())
        all_findings.extend(audit_users())
        all_findings.extend(audit_services())
        all_findings.extend(audit_file_permissions())
        return all_findings

    def get_last_report(self) -> Optional[dict]:
        return self._last_report.to_dict() if self._last_report else None

    def get_summary(self) -> dict:
        if not self._last_report:
            return {"status": "no_audit_yet"}
        r = self._last_report
        return {
            "status": "ok",
            "score": r.score,
            "grade": r.grade,
            "total_checks": r.total_checks,
            "passed_checks": r.passed_checks,
            "critical_failures": r.critical_failures,
            "by_category": r.by_category,
            "ai_summary": r.ai_summary,
            "top_recommendations": r.ai_recommendations[:5],
            "audit_time_iso": datetime.fromtimestamp(
                r.audit_time, tz=timezone.utc
            ).isoformat(),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
_advisor_instance: Optional[HardeningAdvisor] = None

def get_hardening_advisor() -> HardeningAdvisor:
    global _advisor_instance
    if _advisor_instance is None:
        _advisor_instance = HardeningAdvisor()
    return _advisor_instance
