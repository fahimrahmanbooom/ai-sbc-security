"""
AI SBC Security - Main FastAPI Application
Boots all monitors, AI engines, and serves the dashboard.
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError

from .database.db import init_db, AsyncSessionLocal, Alert, MetricSnapshot
from .auth.routes import router as auth_router
from .api.dashboard import router as dashboard_router, broadcast_update
from .monitors.system import get_system_monitor
from .monitors.network import get_network_monitor
from .monitors.log_watcher import get_log_watcher
from .ai.anomaly import get_anomaly_detector
from .ai.ids import get_ids_engine
from .ai.log_intel import get_log_intel
from .ai.predictor import get_predictor
from .ai.fim import get_fim
from .ai.vuln_scanner import get_vuln_scanner
from .ai.hardening import get_hardening_advisor
from .ai.honeypot import get_honeypot
from .ai.federated import get_fl_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ai_sbc")

STATIC_DIR = Path(__file__).parent / "static"


# ─── Lifecycle ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start all background tasks on startup."""
    logger.info("╔══════════════════════════════════════╗")
    logger.info("║     AI SBC Security — Starting Up     ║")
    logger.info("╚══════════════════════════════════════╝")

    # Init database
    await init_db()
    logger.info("✓ Database initialized")

    # Initialize singletons
    sys_mon = get_system_monitor()
    net_mon = get_network_monitor()
    log_watcher = get_log_watcher()
    anomaly = get_anomaly_detector()
    ids = get_ids_engine()
    log_intel = get_log_intel()
    predictor = get_predictor()
    fim = get_fim()
    vuln_scanner = get_vuln_scanner()
    hardening = get_hardening_advisor()
    honeypot = get_honeypot()
    fl_client = get_fl_client()

    # Wire up callbacks: system monitor → anomaly + db + predictor
    async def on_system_metrics(metrics: dict, alerts: list):
        # Feed anomaly detector
        await anomaly.add_to_baseline(metrics)
        result = await anomaly.detect(metrics)

        # Feed predictor
        threat_score = result.anomaly_score
        await predictor.record(threat_score)

        # Persist metric snapshot
        async with AsyncSessionLocal() as db:
            snap = MetricSnapshot(
                cpu_percent=metrics.get("cpu_percent", 0),
                ram_percent=metrics.get("ram_percent", 0),
                disk_percent=metrics.get("disk_percent", 0),
                net_bytes_sent=metrics.get("net_bytes_sent", 0),
                net_bytes_recv=metrics.get("net_bytes_recv", 0),
                net_packets_sent=metrics.get("net_packets_sent", 0),
                net_packets_recv=metrics.get("net_packets_recv", 0),
                cpu_temp=metrics.get("cpu_temp"),
                threat_level=threat_score
            )
            db.add(snap)

            # Persist anomaly alerts
            if result.is_anomaly and result.anomaly_score > 0.5:
                alert = Alert(
                    severity=result.severity,
                    category="anomaly",
                    title=f"AI Anomaly Detected (score: {result.anomaly_score:.2f})",
                    description=result.description,
                    threat_score=result.anomaly_score * 10
                )
                db.add(alert)

            # Persist resource alerts
            for a in alerts:
                alert = Alert(
                    severity=a.get("severity", "medium"),
                    category="system",
                    title=a.get("message", "System alert"),
                    description=str(a),
                    threat_score=6.0 if a.get("severity") == "high" else 4.0
                )
                db.add(alert)

            await db.commit()

        # Broadcast to WebSocket clients
        await broadcast_update({
            "type": "metrics_update",
            "metrics": metrics,
            "anomaly": {
                "is_anomaly": result.is_anomaly,
                "score": result.anomaly_score,
                "severity": result.severity
            }
        })

    # Wire up log watcher → IDS + log intel
    async def on_log_line(line: str, filepath: str):
        # IDS analysis
        ids_alert = await ids.analyze_log_line(line, filepath)
        if ids_alert and ids_alert.threat_score >= 5.0:
            async with AsyncSessionLocal() as db:
                alert = Alert(
                    severity="critical" if ids_alert.threat_score >= 8 else "high",
                    category="intrusion",
                    title=f"IDS: {ids_alert.attack_type.value.replace('_', ' ').title()}",
                    description=ids_alert.description,
                    source_ip=ids_alert.source_ip,
                    threat_score=ids_alert.threat_score
                )
                db.add(alert)
                await db.commit()
            await broadcast_update({
                "type": "ids_alert",
                "alert": {
                    "attack_type": ids_alert.attack_type.value,
                    "source_ip": ids_alert.source_ip,
                    "threat_score": ids_alert.threat_score,
                    "description": ids_alert.description,
                    "mitre": ids_alert.mitre_technique
                }
            })

        # Log intelligence
        entry = await log_intel.process_line(line, filepath)

    # Wire FIM callbacks → alerts + websocket
    async def on_fim_event(event):
        async with AsyncSessionLocal() as db:
            alert = Alert(
                severity=event.severity,
                category="fim",
                title=f"FIM: {event.event_type.title()} — {event.path}",
                description=event.description,
                threat_score=event.ml_score * 10,
            )
            db.add(alert)
            await db.commit()
        await broadcast_update({
            "type": "fim_event",
            "event": event.to_dict(),
        })

    fim.on_event(on_fim_event)

    # Wire honeypot → IDS + alerts
    async def on_honeypot_alert(probe):
        async with AsyncSessionLocal() as db:
            alert = Alert(
                severity="high" if probe.threat_score >= 0.8 else "medium",
                category="honeypot",
                title=f"Honeypot: {probe.threat_label.replace('_', ' ').title()} on {probe.service}",
                description=f"Probe from {probe.src_ip}:{probe.src_port} → port {probe.honeypot_port}",
                source_ip=probe.src_ip,
                threat_score=probe.threat_score * 10,
            )
            db.add(alert)
            await db.commit()
        await broadcast_update({
            "type": "honeypot_probe",
            "probe": probe.to_dict(),
        })

    honeypot.on_alert(on_honeypot_alert)

    # Wire federated learning to anomaly detector. Pass the detector itself —
    # the FL client drills into .model.named_steps['iforest'] on each upload,
    # so retrains that swap detector.model are picked up automatically.
    fl_client.set_model_reference(anomaly)

    # Register callbacks
    sys_mon.add_callback(on_system_metrics)
    log_watcher.add_processor(on_log_line)

    # Start all background services
    await fim.start()
    await vuln_scanner.start()
    await hardening.start()
    await honeypot.start()
    await fl_client.start()

    tasks = [
        asyncio.create_task(sys_mon.run(), name="system_monitor"),
        asyncio.create_task(net_mon.run(), name="network_monitor"),
        asyncio.create_task(log_watcher.run(), name="log_watcher"),
        asyncio.create_task(_correlation_loop(log_intel), name="correlation"),
    ]
    logger.info(f"✓ {len(tasks)} background monitors started")
    logger.info("✓ FIM, Vulnerability Scanner, Hardening Advisor, Honeypot active")
    logger.info("✓ AI SBC Security is operational — dashboard at http://localhost:7443")

    yield

    # Shutdown
    for task in tasks:
        task.cancel()
    sys_mon.stop()
    net_mon.stop()
    log_watcher.stop()
    await fim.stop()
    await vuln_scanner.stop()
    await hardening.stop()
    await honeypot.stop()
    await fl_client.stop()
    logger.info("AI SBC Security stopped")


async def _correlation_loop(log_intel):
    """Run log correlation every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        insights = await log_intel.run_correlation()
        if insights:
            for insight in insights:
                async with AsyncSessionLocal() as db:
                    alert = Alert(
                        severity=insight.severity,
                        category="log",
                        title=insight.title,
                        description=insight.description,
                        threat_score=7.0 if insight.severity == "critical" else 5.0
                    )
                    db.add(alert)
                    await db.commit()
            await broadcast_update({
                "type": "log_insights",
                "count": len(insights),
                "top_insight": {
                    "title": insights[0].title,
                    "severity": insights[0].severity
                } if insights else None
            })


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI SBC Security",
    description="AI-powered security monitoring for Single Board Computers",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS — defaults to same-origin only (the dashboard is served from the same
# host as the API, so CORS isn't needed in production). Set CORS_ORIGINS to
# a comma-separated list of origins for cross-origin dev, or "*" for fully
# open (which forces credentials off, since browsers reject "*" + creds).
_cors_env = os.environ.get("CORS_ORIGINS", "").strip()
if _cors_env == "*":
    _cors_origins = ["*"]
    _cors_credentials = False
elif _cors_env:
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
    _cors_credentials = True
else:
    _cors_origins = []
    _cors_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Convert Pydantic validation errors to a plain string so the frontend can display them."""
    msgs = []
    for err in exc.errors():
        msg = str(err.get("msg", "Validation error")).replace("Value error, ", "")
        field = err.get("loc", [])[-1] if err.get("loc") else ""
        msgs.append(f"{field}: {msg}" if field and field != "body" else msg)
    return JSONResponse(status_code=422, content={"detail": " · ".join(msgs)})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# API Routes
app.include_router(auth_router)
app.include_router(dashboard_router)

# Serve React frontend (static build)
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Catch-all: serve React app for non-API routes."""
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return JSONResponse(status_code=503, content={"detail": "Frontend not built"})
