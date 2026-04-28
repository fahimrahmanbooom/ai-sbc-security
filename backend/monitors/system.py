"""
AI SBC Security - System Resource Monitor
Monitors CPU, RAM, disk, temperature, processes.
Optimized for SBC constraints — minimal CPU overhead.
"""
import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

import psutil

from ..utils.time import utcnow

logger = logging.getLogger("ai_sbc.monitor.system")


def get_cpu_temp() -> Optional[float]:
    """Read CPU temperature — supports Raspberry Pi, generic Linux thermal zones."""
    # Raspberry Pi / ARM thermal zone
    for path in [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
    ]:
        try:
            with open(path) as f:
                return float(f.read().strip()) / 1000.0
        except:
            pass
    # psutil sensor fallback
    try:
        temps = psutil.sensors_temperatures()
        for key in ["cpu_thermal", "coretemp", "k10temp", "cpu-thermal", "soc_thermal"]:
            if key in temps and temps[key]:
                return temps[key][0].current
    except:
        pass
    return None


def get_system_metrics() -> Dict[str, Any]:
    """Collect a full snapshot of system metrics."""
    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    procs = list(psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status", "cmdline"]))

    # Top processes by CPU
    top_procs = sorted(
        [{"pid": p.info["pid"], "name": p.info["name"],
          "cpu": p.info["cpu_percent"], "mem": p.info["memory_percent"],
          "status": p.info["status"]}
         for p in procs if p.info["cpu_percent"] is not None],
        key=lambda x: x["cpu"], reverse=True
    )[:10]

    # Network connections count
    try:
        connections = len(psutil.net_connections())
    except:
        connections = 0

    # Load averages
    try:
        load_avg = os.getloadavg()
    except:
        load_avg = (0.0, 0.0, 0.0)

    # Disk I/O
    try:
        disk_io = psutil.disk_io_counters()
        disk_read_mb = round(disk_io.read_bytes / 1024 / 1024, 2) if disk_io else 0
        disk_write_mb = round(disk_io.write_bytes / 1024 / 1024, 2) if disk_io else 0
    except:
        disk_read_mb = disk_write_mb = 0

    return {
        "timestamp": utcnow().isoformat(),
        "cpu_percent": round(cpu, 1),
        "cpu_count": psutil.cpu_count(),
        "cpu_freq_mhz": round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else None,
        "load_avg_1": round(load_avg[0], 2),
        "load_avg_5": round(load_avg[1], 2),
        "load_avg_15": round(load_avg[2], 2),
        "ram_total_mb": round(ram.total / 1024 / 1024, 0),
        "ram_used_mb": round(ram.used / 1024 / 1024, 0),
        "ram_percent": round(ram.percent, 1),
        "ram_available_mb": round(ram.available / 1024 / 1024, 0),
        "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 1),
        "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 1),
        "disk_percent": round(disk.percent, 1),
        "disk_read_mb_total": disk_read_mb,
        "disk_write_mb_total": disk_write_mb,
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "net_packets_sent": net.packets_sent,
        "net_packets_recv": net.packets_recv,
        "net_errin": net.errin,
        "net_errout": net.errout,
        "open_connections": connections,
        "processes_count": len(procs),
        "cpu_temp": get_cpu_temp(),
        "top_processes": top_procs,
    }


class SystemMonitor:
    """Async system resource monitor with alert thresholds."""

    def __init__(self, poll_interval: int = 5,
                 cpu_alert: float = 90, ram_alert: float = 90,
                 disk_alert: float = 85, temp_alert: float = 80):
        self.poll_interval = poll_interval
        self.cpu_alert = cpu_alert
        self.ram_alert = ram_alert
        self.disk_alert = disk_alert
        self.temp_alert = temp_alert
        self._prev_net: Optional[Dict] = None
        self._running = False
        self._callbacks = []
        self._latest: Dict = {}

    def add_callback(self, fn):
        self._callbacks.append(fn)

    async def _run_callbacks(self, metrics: Dict, alerts: List[Dict]):
        for fn in self._callbacks:
            try:
                await fn(metrics, alerts)
            except Exception as e:
                logger.error(f"System monitor callback error: {e}")

    def _compute_rates(self, current: Dict) -> Dict:
        """Compute per-second network rates from cumulative counters."""
        rates = {}
        if self._prev_net:
            dt = self.poll_interval
            rates["net_bytes_sent_rate"] = max(0, (current["net_bytes_sent"] - self._prev_net["net_bytes_sent"]) / dt)
            rates["net_bytes_recv_rate"] = max(0, (current["net_bytes_recv"] - self._prev_net["net_bytes_recv"]) / dt)
            rates["net_packets_sent_rate"] = max(0, (current["net_packets_sent"] - self._prev_net["net_packets_sent"]) / dt)
            rates["net_packets_recv_rate"] = max(0, (current["net_packets_recv"] - self._prev_net["net_packets_recv"]) / dt)
        else:
            rates = {k: 0 for k in ["net_bytes_sent_rate", "net_bytes_recv_rate",
                                      "net_packets_sent_rate", "net_packets_recv_rate"]}
        self._prev_net = {k: current[k] for k in ["net_bytes_sent", "net_bytes_recv",
                                                    "net_packets_sent", "net_packets_recv"]}
        return rates

    def _check_alerts(self, metrics: Dict) -> List[Dict]:
        alerts = []
        checks = [
            ("cpu_percent", self.cpu_alert, "CPU", "%"),
            ("ram_percent", self.ram_alert, "RAM", "%"),
            ("disk_percent", self.disk_alert, "Disk", "%"),
        ]
        for key, threshold, name, unit in checks:
            val = metrics.get(key, 0)
            if val and val > threshold:
                severity = "critical" if val > threshold + 5 else "high"
                alerts.append({
                    "type": "resource",
                    "severity": severity,
                    "message": f"{name} usage at {val}{unit} (threshold: {threshold}{unit})",
                    "value": val,
                    "threshold": threshold
                })
        temp = metrics.get("cpu_temp")
        if temp and temp > self.temp_alert:
            alerts.append({
                "type": "temperature",
                "severity": "critical" if temp > self.temp_alert + 5 else "high",
                "message": f"CPU temperature {temp:.1f}°C exceeds threshold",
                "value": temp,
                "threshold": self.temp_alert
            })
        return alerts

    async def run(self):
        self._running = True
        logger.info("System monitor started")
        while self._running:
            try:
                raw = get_system_metrics()
                rates = self._compute_rates(raw)
                metrics = {**raw, **rates}
                alerts = self._check_alerts(metrics)
                self._latest = metrics
                await self._run_callbacks(metrics, alerts)
            except Exception as e:
                logger.error(f"System monitor error: {e}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    def get_latest(self) -> Dict:
        return self._latest


_monitor: Optional[SystemMonitor] = None

def get_system_monitor() -> SystemMonitor:
    global _monitor
    if _monitor is None:
        _monitor = SystemMonitor()
    return _monitor
