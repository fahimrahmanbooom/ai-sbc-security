"""
AI SBC Security - Dashboard API Routes
REST + WebSocket endpoints for the React frontend.
"""
import asyncio
import json
import logging
import os
import re as _re
import subprocess
import threading
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ..database.db import get_db, Alert, MetricSnapshot, ThreatEvent, BlockedIP, AuditLog
from ..auth.routes import get_current_user
from ..database.db import User
from ..monitors.system import get_system_monitor
from ..monitors.network import get_network_monitor
from ..ai.anomaly import get_anomaly_detector
from ..ai.ids import get_ids_engine
from ..ai.log_intel import get_log_intel
from ..ai.predictor import get_predictor
from ..ai.fim import get_fim
from ..ai.vuln_scanner import get_vuln_scanner
from ..ai.hardening import get_hardening_advisor
from ..ai.honeypot import get_honeypot
from ..ai.federated import get_fl_client

router = APIRouter(prefix="/api", tags=["dashboard"])
logger = logging.getLogger("ai_sbc.api.dashboard")


class ConnectionManager:
    """WebSocket connection manager for real-time updates."""
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"WebSocket connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: Dict):
        msg = json.dumps(data, default=str)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


async def broadcast_update(data: Dict):
    await ws_manager.broadcast(data)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket stream — sends system metrics every 3s."""
    await ws_manager.connect(websocket)
    try:
        while True:
            sys_mon = get_system_monitor()
            net_mon = get_network_monitor()
            anomaly = get_anomaly_detector()
            ids = get_ids_engine()

            metrics = sys_mon.get_latest()
            net_data = net_mon.get_latest()
            ids_stats = ids.get_stats()
            anomaly_stats = anomaly.get_stats()

            await websocket.send_text(json.dumps({
                "type": "live_update",
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": {
                    "cpu_percent": metrics.get("cpu_percent", 0),
                    "ram_percent": metrics.get("ram_percent", 0),
                    "disk_percent": metrics.get("disk_percent", 0),
                    "cpu_temp": metrics.get("cpu_temp"),
                    "load_avg_1": metrics.get("load_avg_1", 0),
                    "net_bytes_recv_rate": metrics.get("net_bytes_recv_rate", 0),
                    "net_bytes_sent_rate": metrics.get("net_bytes_sent_rate", 0),
                    "open_connections": metrics.get("open_connections", 0),
                },
                "network": {
                    "total_connections": net_data.get("total_connections", 0),
                    "suspicious_connections": net_data.get("suspicious_connections", 0),
                },
                "ai": {
                    "anomaly_score": anomaly_stats.get("recent_anomalies", 0),
                    "ids_alerts": ids_stats.get("total_alerts", 0),
                    "critical_alerts": ids_stats.get("critical_alerts", 0),
                }
            }, default=str))
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)


@router.get("/health")
async def health():
    return {"status": "operational", "timestamp": datetime.utcnow().isoformat()}


@router.get("/dashboard/overview")
async def get_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Main dashboard overview — all stats in one call."""
    sys_mon = get_system_monitor()
    net_mon = get_network_monitor()
    anomaly = get_anomaly_detector()
    ids = get_ids_engine()
    log_intel = get_log_intel()
    predictor = get_predictor()

    metrics = sys_mon.get_latest()
    net_data = net_mon.get_latest()

    # Recent alerts from DB
    alert_result = await db.execute(
        select(Alert).order_by(desc(Alert.timestamp)).limit(5)
    )
    recent_alerts = alert_result.scalars().all()

    # Alert counts by severity
    for sev in ["critical", "high", "medium", "low"]:
        r = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.severity == sev,
                Alert.resolved == False
            )
        )

    # Total unresolved
    unresolved_r = await db.execute(
        select(func.count(Alert.id)).where(Alert.resolved == False)
    )
    unresolved_count = unresolved_r.scalar() or 0

    # Blocked IPs
    blocked_r = await db.execute(select(func.count(BlockedIP.id)))
    blocked_count = blocked_r.scalar() or 0

    # 24h metric history
    since = datetime.utcnow() - timedelta(hours=24)
    hist_r = await db.execute(
        select(MetricSnapshot).where(MetricSnapshot.timestamp > since)
        .order_by(MetricSnapshot.timestamp)
    )
    history = hist_r.scalars().all()

    pred_stats = predictor.get_stats()
    ids_stats = ids.get_stats()
    log_stats = log_intel.get_stats()
    anomaly_stats = anomaly.get_stats()

    return {
        "system": {
            **{k: metrics.get(k) for k in [
                "cpu_percent", "ram_percent", "disk_percent",
                "cpu_temp", "load_avg_1", "load_avg_5", "load_avg_15",
                "ram_used_mb", "ram_total_mb",
                "disk_used_gb", "disk_total_gb",
                "processes_count", "open_connections",
                "top_processes"
            ]},
        },
        "network": {
            "total_connections": net_data.get("total_connections", 0),
            "established": net_data.get("established", 0),
            "suspicious": net_data.get("suspicious_connections", 0),
            "interfaces": net_data.get("interfaces", []),
        },
        "security": {
            "unresolved_alerts": unresolved_count,
            "blocked_ips": blocked_count,
            "ids_total_alerts": ids_stats.get("total_alerts", 0),
            "ids_critical": ids_stats.get("critical_alerts", 0),
            "unique_attackers": ids_stats.get("unique_attackers", 0),
            "top_rule_hits": ids_stats.get("top_rule_hits", {}),
        },
        "ai": {
            "anomaly": anomaly_stats,
            "log_intel": log_stats,
            "predictor": pred_stats,
        },
        "recent_alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity,
                "category": a.category,
                "title": a.title,
                "threat_score": a.threat_score,
                "source_ip": a.source_ip,
                "acknowledged": a.acknowledged,
            }
            for a in recent_alerts
        ],
        "metric_history": [
            {
                "timestamp": h.timestamp.isoformat(),
                "cpu": h.cpu_percent,
                "ram": h.ram_percent,
                "disk": h.disk_percent,
                "threat_level": h.threat_level,
                "net_recv": h.net_bytes_recv,
                "net_sent": h.net_bytes_sent,
            }
            for h in history[-100:]  # Last 100 points
        ],
    }


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    resolved: Optional[bool] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Alert).order_by(desc(Alert.timestamp))
    if severity:
        query = query.where(Alert.severity == severity)
    if category:
        query = query.where(Alert.category == category)
    if resolved is not None:
        query = query.where(Alert.resolved == resolved)
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()
    return {"alerts": [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "category": a.category,
            "title": a.title,
            "description": a.description,
            "source_ip": a.source_ip,
            "geo_country": a.geo_country,
            "geo_city": a.geo_city,
            "threat_score": a.threat_score,
            "acknowledged": a.acknowledged,
            "resolved": a.resolved,
        }
        for a in alerts
    ], "total": len(alerts)}


@router.patch("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    await db.commit()
    return {"message": "Alert acknowledged"}


@router.patch("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    await db.commit()
    return {"message": "Alert resolved"}


@router.get("/network/connections")
async def get_connections(current_user: User = Depends(get_current_user)):
    from ..monitors.network import get_active_connections
    return {"connections": get_active_connections()}


@router.get("/ai/forecast")
async def get_forecast(current_user: User = Depends(get_current_user)):
    predictor = get_predictor()
    forecast = await predictor.generate_forecast()
    return {
        "generated_at": forecast.generated_at.isoformat(),
        "overall_risk": forecast.overall_risk,
        "trend": forecast.trend,
        "trend_strength": forecast.trend_strength,
        "peak_threat_hour": forecast.peak_threat_hour,
        "peak_threat_score": forecast.peak_threat_score,
        "summary": forecast.summary,
        "recommendations": forecast.recommendations,
        "hourly_predictions": forecast.hourly_predictions,
    }


@router.get("/ai/insights")
async def get_insights(current_user: User = Depends(get_current_user)):
    log_intel = get_log_intel()
    ids = get_ids_engine()
    insights = log_intel.get_recent_insights(20)
    recent_ids = ids.get_recent_alerts(20, min_score=5.0)
    return {
        "log_insights": [
            {
                "generated_at": i.generated_at.isoformat(),
                "title": i.title,
                "description": i.description,
                "severity": i.severity,
                "affected_ips": i.affected_ips,
                "event_count": i.event_count,
                "recommendations": i.recommendations,
            }
            for i in insights
        ],
        "ids_alerts": [
            {
                "timestamp": a.timestamp.isoformat(),
                "attack_type": a.attack_type,
                "source_ip": a.source_ip,
                "threat_score": a.threat_score,
                "description": a.description,
                "mitre_technique": a.mitre_technique,
            }
            for a in recent_ids
        ]
    }


@router.get("/blocked-ips")
async def get_blocked_ips(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(BlockedIP).order_by(desc(BlockedIP.blocked_at)))
    ips = result.scalars().all()
    return {"blocked_ips": [
        {
            "id": ip.id,
            "ip_address": ip.ip_address,
            "blocked_at": ip.blocked_at.isoformat(),
            "reason": ip.reason,
            "auto_blocked": ip.auto_blocked,
        }
        for ip in ips
    ]}


@router.post("/blocked-ips")
async def block_ip(
    data: Dict[str, str],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    ip = data.get("ip_address", "").strip()
    reason = data.get("reason", "Manual block")
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")
    existing = await db.execute(select(BlockedIP).where(BlockedIP.ip_address == ip))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="IP already blocked")
    blocked = BlockedIP(ip_address=ip, reason=reason, auto_blocked=False)
    db.add(blocked)
    await db.commit()
    return {"message": f"IP {ip} blocked successfully"}


@router.delete("/blocked-ips/{ip_id}")
async def unblock_ip(
    ip_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(BlockedIP).where(BlockedIP.id == ip_id))
    ip = result.scalar_one_or_none()
    if not ip:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ip)
    await db.commit()
    return {"message": "IP unblocked"}


@router.get("/audit-log")
async def get_audit_log(
    limit: int = Query(100, le=1000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    result = await db.execute(
        select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
    )
    logs = result.scalars().all()
    return {"logs": [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "action": l.action,
            "ip_address": l.ip_address,
            "success": l.success,
            "details": l.details,
        }
        for l in logs
    ]}

# ─── File Integrity Monitor API ───────────────────────────────────────────────

@router.get("/fim/status")
async def fim_status(current_user: User = Depends(get_current_user)):
    fim = get_fim()
    return {**fim.get_stats(), "baseline": fim.get_baseline_summary()}


@router.get("/fim/events")
async def fim_events(
    limit: int = Query(50, le=200),
    current_user: User = Depends(get_current_user),
):
    fim = get_fim()
    return {"events": fim.get_recent_events(limit)}


@router.post("/fim/scan")
async def fim_force_scan(current_user: User = Depends(get_current_user)):
    fim = get_fim()
    result = await fim.force_rescan()
    return result


@router.post("/fim/rebaseline")
async def fim_rebaseline(current_user: User = Depends(get_current_user)):
    """Re-establish baseline from current state. Use only after verified clean system."""
    fim = get_fim()
    return await fim.rebaseline()


# ─── Vulnerability Scanner API ────────────────────────────────────────────────

@router.get("/vulns/summary")
async def vuln_summary(current_user: User = Depends(get_current_user)):
    scanner = get_vuln_scanner()
    return scanner.get_summary()


@router.get("/vulns/findings")
async def vuln_findings(
    severity: Optional[str] = None,
    limit: int = Query(50, le=200),
    current_user: User = Depends(get_current_user),
):
    scanner = get_vuln_scanner()
    result = scanner.get_last_result()
    if not result:
        return {"status": "no_scan_yet", "findings": []}
    findings = result.get("findings", [])
    if severity:
        findings = [f for f in findings if f.get("ai_priority_label") == severity]
    return {"findings": findings[:limit], "total": len(findings)}


@router.post("/vulns/scan")
async def vuln_scan_now(current_user: User = Depends(get_current_user)):
    scanner = get_vuln_scanner()
    result = await scanner.run_scan_now()
    return {
        "packages_scanned": result.packages_scanned,
        "vulnerabilities_found": result.vulnerabilities_found,
        "by_severity": result.by_severity,
        "scan_duration_s": result.scan_duration_s,
    }


# ─── Hardening Advisor API ────────────────────────────────────────────────────

@router.get("/hardening/summary")
async def hardening_summary(current_user: User = Depends(get_current_user)):
    advisor = get_hardening_advisor()
    return advisor.get_summary()


@router.get("/hardening/report")
async def hardening_report(current_user: User = Depends(get_current_user)):
    advisor = get_hardening_advisor()
    report = advisor.get_last_report()
    if not report:
        return {"status": "no_audit_yet"}
    return report


@router.post("/hardening/audit")
async def hardening_audit_now(current_user: User = Depends(get_current_user)):
    advisor = get_hardening_advisor()
    report = await advisor.run_audit_now()
    return {
        "score": report.score,
        "grade": report.grade,
        "total_checks": report.total_checks,
        "passed_checks": report.passed_checks,
        "critical_failures": report.critical_failures,
        "ai_summary": report.ai_summary,
        "top_recommendations": report.ai_recommendations[:5],
    }


@router.post("/hardening/autofix")
async def hardening_autofix(body: dict, current_user: User = Depends(get_current_user)):
    """Run the auto-fix command for a specific hardening check."""
    check_id = body.get("check_id", "")
    if not check_id:
        raise HTTPException(status_code=400, detail="check_id is required")

    advisor = get_hardening_advisor()
    report = advisor.get_last_report()
    if not report:
        raise HTTPException(status_code=404, detail="No audit report available. Run an audit first.")

    findings = report.get("findings", [])
    finding = next((f for f in findings if f.get("check_id") == check_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Check '{check_id}' not found in last report")

    fix_cmd = finding.get("fix_command", "").strip()
    if not fix_cmd:
        raise HTTPException(status_code=400, detail="No fix command available for this check")

    # Strip leading `sudo` — the service already runs as root under systemd.
    # Running sudo inside a root process with no TTY/sudoers causes PERM errors.
    clean_cmd = _re.sub(r'^\s*sudo\s+', '', fix_cmd)

    try:
        result = subprocess.run(
            clean_cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500,
                detail=f"Fix command failed (exit {result.returncode}): {result.stderr[:300]}")
        return {
            "status": "applied",
            "check_id": check_id,
            "stdout": result.stdout[:500],
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Fix command timed out (30s limit)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Honeypot API ─────────────────────────────────────────────────────────────

@router.get("/honeypot/stats")
async def honeypot_stats(current_user: User = Depends(get_current_user)):
    hp = get_honeypot()
    return hp.get_stats()


@router.get("/honeypot/probes")
async def honeypot_probes(
    limit: int = Query(50, le=200),
    current_user: User = Depends(get_current_user),
):
    hp = get_honeypot()
    return {"probes": hp.get_recent_probes(limit)}


@router.get("/honeypot/clusters")
async def honeypot_clusters(current_user: User = Depends(get_current_user)):
    hp = get_honeypot()
    return {"clusters": hp.get_clusters()}


@router.get("/honeypot/attackers")
async def honeypot_top_attackers(
    limit: int = Query(10, le=50),
    current_user: User = Depends(get_current_user),
):
    hp = get_honeypot()
    return {"attackers": hp.get_top_attackers(limit)}


# ─── Federated Learning API ───────────────────────────────────────────────────

@router.get("/federated/status")
async def federated_status(current_user: User = Depends(get_current_user)):
    fl = get_fl_client()
    return fl.get_status()


@router.post("/federated/enable")
async def federated_enable(
    data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
):
    fl = get_fl_client()
    enabled = bool(data.get("enabled", False))
    fl.configure(enabled)
    if enabled:
        await fl.start()
    else:
        await fl.stop()
    return {"enabled": enabled, "message": f"Federated learning {'enabled' if enabled else 'disabled'}"}


# ─── System Update API ────────────────────────────────────────────────────────

def _git(*args, cwd=None) -> str:
    """Run a git command and return stripped stdout. Raises on non-zero exit."""
    result = subprocess.run(
        ["git"] + list(args),
        capture_output=True, text=True, cwd=cwd or _install_dir(),
    )
    return result.stdout.strip()


def _install_dir() -> str:
    """Return the root directory of the git repo (two levels up from this file)."""
    this = os.path.abspath(__file__)          # backend/api/dashboard.py
    return os.path.dirname(os.path.dirname(os.path.dirname(this)))  # repo root


@router.get("/system/version")
async def system_version(current_user: User = Depends(get_current_user)):
    """Compare local HEAD to origin/main and return update info."""
    try:
        repo = _install_dir()
        # Fetch quietly so we can compare without changing working tree
        subprocess.run(["git", "fetch", "origin", "main", "--quiet"],
                       capture_output=True, cwd=repo, timeout=15)
        local_sha  = _git("rev-parse", "HEAD", cwd=repo)
        remote_sha = _git("rev-parse", "origin/main", cwd=repo)
        # Short version from tag or commit count
        try:
            local_ver  = _git("describe", "--tags", "--always", cwd=repo)
            remote_ver = _git("describe", "--tags", "--always", "origin/main", cwd=repo)
        except Exception:
            local_ver  = local_sha[:7]
            remote_ver = remote_sha[:7]

        return {
            "current_sha":      local_sha[:7],
            "latest_sha":       remote_sha[:7],
            "update_available": local_sha != remote_sha,
            "current_version":  local_ver,
            "latest_version":   remote_ver,
        }
    except Exception as e:
        logger.warning(f"Version check failed: {e}")
        return {
            "current_sha": "unknown", "latest_sha": "unknown",
            "update_available": False, "current_version": "unknown",
            "latest_version": "unknown",
        }


_update_lock = threading.Lock()


@router.post("/system/update")
async def system_update(current_user: User = Depends(get_current_user)):
    """Pull latest code, rebuild frontend if changed, restart service."""
    if not _update_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="An update is already in progress")

    async def _run():
        repo = _install_dir()
        frontend = os.path.join(repo, "frontend")
        static   = os.path.join(repo, "backend", "static")

        async def prog(step: str, detail: str = "", done: bool = False, error: bool = False):
            await ws_manager.broadcast({
                "type":   "update_progress",
                "step":   step,
                "detail": detail,
                "done":   done,
                "error":  error,
                "ts":     datetime.utcnow().isoformat(),
            })

        try:
            await prog("Checking for updates…")

            # Record old HEAD before pull
            old_sha = _git("rev-parse", "HEAD", cwd=repo)

            await prog("Fetching latest code…")
            fetch = subprocess.run(
                ["git", "fetch", "origin", "main"],
                capture_output=True, text=True, cwd=repo, timeout=60,
            )
            if fetch.returncode != 0:
                await prog("Git fetch failed", fetch.stderr[:300], error=True)
                return

            # Fix directory permissions so git can unlink/overwrite files.
            # The service's CapabilityBoundingSet drops CAP_DAC_OVERRIDE so we
            # must ensure every directory under the repo is writable by its owner.
            await prog("Fixing permissions…")
            subprocess.run(
                ["find", str(repo), "-not", "-path", "*/.git/*",
                 "-type", "d", "-exec", "chmod", "u+rwx", "{}", "+"],
                capture_output=True, cwd=repo,
            )
            subprocess.run(
                ["find", str(repo), "-not", "-path", "*/.git/*",
                 "-type", "f", "-exec", "chmod", "u+rw", "{}", "+"],
                capture_output=True, cwd=repo,
            )
            # Also ensure .git itself is writable (needed to update .git/index)
            subprocess.run(
                ["chmod", "-R", "u+rw", os.path.join(str(repo), ".git")],
                capture_output=True,
            )

            # Hard-reset to remote — handles diverged branches cleanly
            await prog("Applying update…")
            reset = subprocess.run(
                ["git", "reset", "--hard", "origin/main"],
                capture_output=True, text=True, cwd=repo, timeout=30,
            )
            if reset.returncode != 0:
                await prog("Git reset failed", reset.stderr[:300], error=True)
                return

            new_sha = _git("rev-parse", "HEAD", cwd=repo)
            await prog("Code updated", f"{old_sha[:7]} → {new_sha[:7]}")

            # Check if frontend source changed between old and new HEAD
            diff = subprocess.run(
                ["git", "diff", "--name-only", old_sha, new_sha, "--", "frontend/"],
                capture_output=True, text=True, cwd=repo,
            )
            frontend_changed = bool(diff.stdout.strip()) or old_sha == new_sha

            if frontend_changed:
                await prog("Installing frontend dependencies…")
                npm_i = subprocess.run(
                    ["npm", "install"], capture_output=True, text=True,
                    cwd=frontend, timeout=180,
                )
                if npm_i.returncode != 0:
                    await prog("npm install failed", npm_i.stderr[:300], error=True)
                    return

                await prog("Building frontend…")
                npm_b = subprocess.run(
                    ["npm", "run", "build"], capture_output=True, text=True,
                    cwd=frontend, timeout=300,
                )
                if npm_b.returncode != 0:
                    await prog("Frontend build failed", npm_b.stderr[:300], error=True)
                    return

                await prog("Deploying frontend…")
                os.makedirs(static, exist_ok=True)
                subprocess.run(
                    f"cp -r {frontend}/dist/* {static}/",
                    shell=True, check=True,
                )
                await prog("Frontend deployed")
            else:
                await prog("Frontend unchanged — skipping rebuild")

            # Check if backend changed
            back_diff = subprocess.run(
                ["git", "diff", "--name-only", old_sha, new_sha, "--", "backend/"],
                capture_output=True, text=True, cwd=repo,
            )
            backend_changed = bool(back_diff.stdout.strip())

            if backend_changed:
                await prog("Installing backend dependencies…")
                pip = subprocess.run(
                    ["pip", "install", "-r", "requirements.txt", "--break-system-packages",
                     "--quiet"],
                    capture_output=True, text=True,
                    cwd=os.path.join(repo, "backend"), timeout=180,
                )
                if pip.returncode != 0:
                    await prog("pip install warning", pip.stderr[:200])
            else:
                await prog("Backend unchanged — skipping pip install")

            await prog("Restarting service…")
            await ws_manager.broadcast({
                "type": "update_progress", "step": "Update complete — restarting",
                "detail": "Dashboard will reconnect automatically in a few seconds.",
                "done": True, "error": False, "ts": datetime.utcnow().isoformat(),
            })
            # Small delay so the frontend receives the final message
            await asyncio.sleep(1.5)
            subprocess.Popen(
                ["systemctl", "restart", "ai-sbc-security"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            await prog("Update error", str(exc)[:300], error=True)
            logger.error(f"Update failed: {exc}")
        finally:
            _update_lock.release()

    # Run the update in the background so the HTTP response returns immediately
    asyncio.create_task(_run())
    return {"status": "update_started"}
