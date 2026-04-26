<div align="center">

<h1>🛡️ AI SBC Security</h1>
<h3>S E C U R I T Y &nbsp;·&nbsp; A I &nbsp;E D I T I O N</h3>

**AI-powered security monitoring for Single Board Computers & Linux servers**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg?style=flat-square)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/React-18-61dafb.svg?style=flat-square&logo=react)](https://react.dev)
[![ARM64](https://img.shields.io/badge/ARM64-✓-00ffb3.svg?style=flat-square)](https://www.arm.com)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-✓-A22846.svg?style=flat-square&logo=raspberrypi)](https://raspberrypi.org)
[![x86_64](https://img.shields.io/badge/x86__64-✓-blue.svg?style=flat-square)](https://en.wikipedia.org/wiki/X86-64)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/P5P46VPK7)

</div>

---

## ⚡ One-Line Install

```bash
curl -sSL https://raw.githubusercontent.com/fahimrahmanbooom/ai-sbc-security/main/install.sh | bash
```

Open `http://<your-device-ip>:7443` → Create admin account → Set up 2FA → You're protected.

**Uninstall:** `curl -sSL .../install.sh | bash -s -- --uninstall`

---

## What is AI SBC Security?

AI SBC Security is a **free, open-source, AI-first security monitoring platform** purpose-built for single board computers and lightweight Linux servers. Unlike heavyweight SIEM tools that require clusters to run, AI SBC Security boots in seconds on a Raspberry Pi 4 and immediately starts learning and defending your system.

It runs a **4-engine AI stack** — anomaly detection, intrusion detection, log intelligence, and a predictive threat model — all offline, no cloud required. Every alert is scored, correlated, and explained in plain language so you know exactly what's happening and what to do about it.

---

## Features

### 🤖 AI Engine — 4 Neural Security Layers

**Anomaly Detection** — Isolation Forest ML model that builds a behavioral baseline of your system in real time. It tracks 14 concurrent features including CPU, RAM, network rates, login patterns, connection counts, and temporal rhythms. Once trained (typically ~30 minutes), it flags deviations from normal with a confidence-calibrated score, even for novel zero-day attacks that no signature would catch.

**Intrusion Detection System (IDS)** — A hybrid rule-based + behavioral engine with 12 attack categories mapped to MITRE ATT&CK. It detects SSH brute force, port scans, SQL injection, XSS, LFI/RFI path traversal, command injection, reverse shells, privilege escalation attempts, crypto-mining processes, and credential stuffing — all with configurable thresholds and a sliding-window deduplication engine so alerts are meaningful, not noisy.

**Log Intelligence** — A real-time log correlation engine that tails `/var/log/auth.log`, `syslog`, `kern.log`, nginx/apache access logs, fail2ban, and any custom paths. It parses, threat-scores, and correlates events across sources within configurable time windows, automatically surfacing insights like "IP X targeted 5 different users in 3 minutes" or "User Y is being attacked from 8 distinct IPs."

**Predictive Threat Model** — A lightweight time-series forecasting engine (Holt-Winters double exponential smoothing + seasonal decomposition) that learns your system's attack patterns over time and forecasts threat levels for the next 24 hours, hour by hour. It identifies your peak-risk windows, detects escalating trends, and generates proactive recommendations — before the attack peaks.

### 🔐 Security

- **TOTP Two-Factor Authentication** — RFC 6238 compliant TOTP (Google Authenticator, Authy, any standard app). QR code setup in the dashboard. Required at first login.
- **JWT Authentication** — Short-lived access tokens (60 min) + long-lived refresh tokens (7 days) with automatic silent refresh.
- **Account Lockout** — Automatic account lockout after 5 failed login attempts (15-minute cooldown).
- **Audit Log** — Every login, logout, alert action, IP block, and settings change is recorded with timestamp, IP, and user agent.
- **Bcrypt Password Hashing** — Industry-standard bcrypt with configurable rounds.

### 📊 Dashboard

- **Real-Time WebSocket Updates** — The dashboard receives live metric pushes every 3 seconds over a persistent WebSocket, with automatic reconnection.
- **Cyberpunk Dark Theme** — Orbitron display font, JetBrains Mono for data, animated glow effects, scanline overlays, matrix rain login screen, threat-level animations.
- **Framer Motion Animations** — All cards, charts, and alerts animate in with spring physics. Threat level bar morphs in real time. Severity badges pulse on critical alerts.
- **Live Charts** — Recharts-powered area charts for CPU/RAM, network in/out (KB/s), and threat levels. All update live from WebSocket data.
- **Alerts Panel** — Full alert log with severity filtering (critical/high/medium/low/info), acknowledge and resolve actions, threat score ring visualization.
- **AI Insights Tab** — 24-hour forecast chart with peak threat prediction, log correlation insights, IDS alert timeline with MITRE ATT&CK tags.
- **Network Panel** — Live connection table, suspicious connection highlighting, bandwidth gauges, listening port inventory.
- **Blocked IPs Manager** — Add/remove IPs from blocklist, distinguish auto-blocked vs. manually blocked, view block history.
- **Settings** — In-dashboard 2FA setup/teardown with QR code, password change, account info.

### 🖥️ System Monitoring

- CPU percent, frequency, load averages (1/5/15 min)
- RAM total/used/available, swap
- Disk usage per partition
- **CPU temperature** — reads `/sys/class/thermal/` for Raspberry Pi and ARM boards, falls back to `psutil` sensor APIs for x86
- Network: bytes/packets sent/received, per-second rate calculation, error counters
- Active network connections with suspicious port flagging
- Top processes by CPU (live, with PID, name, CPU%, memory%)
- System uptime and load

### 🔧 Operational

- **One-liner installer** — Auto-detects architecture (ARM64, ARM32, x86_64, RISC-V), installs all dependencies, builds the frontend, generates a secret key, installs a systemd service, and starts monitoring — all in one command.
- **Systemd service** — Runs as a persistent background service, auto-starts on boot, auto-restarts on crash.
- **SQLite database** — No external database required. All data (metrics, alerts, users, audit logs, blocked IPs) stored in a single SQLite file.
- **Docker support** — Full `docker-compose.yml` for containerized deployment.
- **YAML configuration** — Every threshold, interval, and AI sensitivity parameter is tunable in `/etc/ai-sbc-security/config.yaml`.
- **Log rotation aware** — The log watcher detects inode changes and handles rotated log files gracefully.
- **Low resource footprint** — Designed for devices with 512MB–4GB RAM. Single-worker uvicorn, scikit-learn Isolation Forest (not PyTorch), streaming data structures, bounded deques. Typical RAM usage: 80–200MB depending on model training state.

---

## Supported Hardware

| Hardware | Architecture | Status |
|---|---|---|
| Raspberry Pi 4 / 5 | ARM64 | ✅ Fully tested |
| Raspberry Pi 3 | ARM64 | ✅ Supported |
| Raspberry Pi Zero 2W | ARM64 | ✅ Supported (light mode) |
| Raspberry Pi Zero (original) | ARM32 | ⚠️ Supported (limited RAM) |
| Orange Pi / Rock Pi / Odroid | ARM64 | ✅ Supported |
| NVIDIA Jetson Nano | ARM64 | ✅ Supported |
| VisionFive 2 | RISC-V 64 | ✅ Experimental |
| x86_64 Ubuntu / Debian | x86_64 | ✅ Fully tested |
| x86_64 VMs (KVM, VMware, etc.) | x86_64 | ✅ Fully tested |
| Any Linux ARM/x86 SBC | Any | ✅ Should work |

---

## Requirements

- **OS:** Debian, Ubuntu, Raspbian, or compatible (apt-based)
- **Python:** 3.9 or higher
- **Node.js:** 16 or higher (for building the frontend; not needed at runtime)
- **RAM:** 256MB minimum, 512MB+ recommended
- **Disk:** 500MB for installation + data
- **Network:** Internet access only needed during install
- **Privileges:** sudo or root (for packet capture and systemd)

---

## Installation

### Option 1 — One-line (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/fahimrahmanbooom/ai-sbc-security/main/install.sh | bash
```

This will:
1. Detect your architecture and OS
2. Install Python 3, Node.js, and system dependencies
3. Clone the repository to `/opt/ai-sbc-security`
4. Create a Python virtual environment and install packages
5. Build the React dashboard
6. Generate a random `SECRET_KEY`
7. Install and start a systemd service
8. Print the dashboard URL

### Option 2 — Docker

```bash
# Clone and start with Docker Compose
git clone https://github.com/fahimrahmanbooom/ai-sbc-security
cd ai-sbc-security
docker-compose up -d
```

Dashboard at `http://localhost:7443`.

### Option 3 — Manual

```bash
# 1. Clone
git clone https://github.com/fahimrahmanbooom/ai-sbc-security
cd ai-sbc-security

# 2. Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Build frontend
cd frontend && npm install && npm run build
cp -r dist ../backend/static && cd ..

# 4. Set env vars
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export DB_PATH=./data/db.sqlite
mkdir -p data/models

# 5. Run
uvicorn backend.main:app --host 0.0.0.0 --port 7443
```

---

## First-Time Setup

1. **Open** `http://<device-ip>:7443`
2. **Create your admin account** — first registered user is automatically admin
3. **Set up 2FA** — you'll be prompted to scan a QR code and verify with your authenticator app
4. **Dashboard is live** — AI models begin warming up immediately

The anomaly detection model reaches full confidence after collecting ~500 samples (~40 minutes at 5-second intervals). Until then, it operates in fallback rule-based mode.

---

## Configuration

Edit `/etc/ai-sbc-security/config.yaml` (installed) or `config/default.yaml` (development):

```yaml
ai:
  anomaly:
    sensitivity: 0.8          # 0.0–1.0 — higher = more alerts
    contamination: 0.05        # Expected outlier fraction
    model_retrain_hours: 24   # Retrain every N hours
  ids:
    alert_threshold: 7         # Minimum score (0–10) to create alert
    block_on_critical: false   # Auto-block IPs on critical IDS hit
  predictor:
    forecast_hours: 24         # Forecast window
    confidence_threshold: 0.75

monitors:
  system:
    cpu_alert_threshold: 90    # Alert when CPU > X%
    temp_alert_celsius: 80     # Alert when temp > X°C
  logs:
    watch_paths:
      - "/var/log/auth.log"
      - "/var/log/nginx/access.log"
      - "/path/to/your/app.log"  # Add custom log paths
```

Restart after changes: `sudo systemctl restart ai-sbc-security`

---

## API Reference

The backend exposes a full REST API. Interactive docs at `http://<device>:7443/api/docs`.

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/login` | Login with username/password/TOTP |
| POST | `/api/auth/register` | Create account |
| GET | `/api/auth/me` | Current user info |
| POST | `/api/auth/totp/setup` | Start TOTP setup, get QR code |
| POST | `/api/auth/totp/verify` | Verify and enable TOTP |
| GET | `/api/dashboard/overview` | Full dashboard data snapshot |
| WS | `/api/ws` | WebSocket live stream |
| GET | `/api/alerts` | Alert log (filterable) |
| PATCH | `/api/alerts/{id}/resolve` | Resolve alert |
| GET | `/api/ai/forecast` | 24h threat forecast |
| GET | `/api/ai/insights` | Log insights + IDS alerts |
| GET | `/api/network/connections` | Live connections |
| GET | `/api/blocked-ips` | Blocklist |
| POST | `/api/blocked-ips` | Block an IP |
| GET | `/api/audit-log` | Audit trail (admin only) |

---

## Architecture

```mermaid
flowchart TB
    Browser["🌐 Browser\nReact 18 + Recharts\nFramer Motion + WebSocket"]

    subgraph Backend["FastAPI Backend"]
        Auth["🔐 Auth\nJWT + TOTP 2FA"]
        API["📡 Dashboard API\nREST + WebSocket"]

        subgraph AI["🤖 AI Engine"]
            IF["Isolation Forest\nAnomaly Detection"]
            IDS["Hybrid IDS\n12 Attack Categories"]
            LC["Log Correlator\nCross-source Intel"]
            HW["Holt-Winters\nThreat Predictor"]
            FIM["File Integrity\nSHA256 + ML"]
            HP["AI Honeypot\nDeception Layer"]
            FL["Federated Learning\nPrivacy-aware"]
        end

        subgraph Monitors["📊 Monitors"]
            SYS["System Monitor\npsutil"]
            NET["Network Monitor\nConnections"]
            LOG["Log Watcher\ninotify"]
        end

        DB["🗄️ SQLite\nAlerts · Metrics · Users\nBlocked IPs · Audit Log"]
    end

    Browser <-->|"WebSocket / REST"| Auth
    Browser <-->|"WebSocket / REST"| API
    Auth --> DB
    API --> DB
    Monitors --> AI
    AI --> API
    AI --> DB
```

---

## MITRE ATT&CK Coverage

The IDS engine maps detections to MITRE ATT&CK techniques:

| Detection | MITRE ID | Tactic |
|---|---|---|
| SSH Brute Force | T1110 | Credential Access |
| Root SSH Attempts | T1078 | Valid Accounts |
| Invalid User SSH | T1110.001 | Credential Stuffing |
| Sudo Escalation | T1548.003 | Privilege Escalation |
| SQL Injection | T1190 | Initial Access |
| XSS | T1059.007 | Execution |
| Path Traversal/LFI | T1083 | Discovery |
| Command Injection | T1059 | Execution |
| Reverse Shell | T1059.004 | Execution |
| Port Scanning | T1046 | Discovery |
| Crypto Mining | T1496 | Impact |
| Malicious Download | T1059.004 | Execution |

---

## Management Commands

```bash
# Service management
sudo systemctl status ai-sbc-security    # Check status
sudo systemctl restart ai-sbc-security   # Restart
sudo journalctl -u ai-sbc-security -f    # Follow logs
sudo journalctl -u ai-sbc-security -n 100 --no-pager  # Last 100 lines

# Configuration
sudo nano /etc/ai-sbc-security/config.yaml   # Edit config
sudo cat /etc/ai-sbc-security/env            # View env vars (secret key, etc.)

# Data
ls /var/lib/ai-sbc-security/                 # Data directory
ls /var/lib/ai-sbc-security/models/          # AI model files
sqlite3 /var/lib/ai-sbc-security/db.sqlite   # Inspect database

# Uninstall
curl -sSL https://raw.githubusercontent.com/fahimrahmanbooom/ai-sbc-security/main/install.sh | bash -s -- --uninstall
```

---

## Security Considerations

**Network Exposure** — The dashboard binds to `0.0.0.0:7443` by default. If your device is exposed to the internet, consider placing it behind a reverse proxy (nginx) with HTTPS and rate limiting. Example nginx config:

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    location / {
        proxy_pass http://localhost:7443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

**2FA is strongly recommended** — Without 2FA, a stolen password is enough to access the dashboard. Enable it during first-time setup.

**Capabilities vs Root** — The installer sets `CAP_NET_RAW` on the Python binary to enable packet capture without running as root. This is scoped to that binary only.

---

## Contributing

Contributions are welcome! Areas where help is especially appreciated:

- Additional IDS signature rules and threat patterns
- GeoIP integration (MaxMind GeoLite2)
- Email/webhook alert notifications
- Additional log format parsers (journald, Docker, custom apps)
- Fail2ban integration for automatic IP blocking
- UI improvements and new dashboard panels
- Testing on additional SBC hardware

Please open an issue before submitting large PRs to discuss the approach.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Free to use, modify, and distribute. Attribution appreciated but not required.

---

<div align="center">

**Built for the SBC community with ❤️ — Open Source forever**

[Report a Bug](https://github.com/fahimrahmanbooom/ai-sbc-security/issues) · 
[Request a Feature](https://github.com/fahimrahmanbooom/ai-sbc-security/issues) · 
[Discussions](https://github.com/fahimrahmanbooom/ai-sbc-security/discussions)

</div>
