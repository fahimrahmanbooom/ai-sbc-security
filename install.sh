#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  AI SBC Security — Interactive Installer v1.0
#  Usage: curl -sSL https://raw.githubusercontent.com/fahimrahmanbooom/ai-sbc-security/main/install.sh | bash
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail
# Note: -e (errexit) intentionally omitted so non-fatal errors don't kill install
# Individual steps use explicit error handling via fail()

# ── Terminal Colors & Styles ──────────────────────────────────────────────────
RESET='\033[0m';    BOLD='\033[1m';    DIM='\033[2m';     ITALIC='\033[3m'
CYAN='\033[0;36m';  BCYAN='\033[1;36m'; GREEN='\033[0;32m'; BGREEN='\033[1;32m'
YELLOW='\033[1;33m'; RED='\033[0;31m';  BRED='\033[1;31m';  BLUE='\033[0;34m'
BBLUE='\033[1;34m'; MAGENTA='\033[0;35m'; BMAGENTA='\033[1;35m'; WHITE='\033[1;37m'
BG_DARK='\033[48;5;233m'; BG_CARD='\033[48;5;234m'

# ── Config ────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/ai-sbc-security"
DATA_DIR="/var/lib/ai-sbc-security"
CONFIG_DIR="/etc/ai-sbc-security"
SERVICE_NAME="ai-sbc-security"
DEFAULT_PORT=7443
REPO_URL="https://github.com/fahimrahmanbooom/ai-sbc-security"
STEPS_TOTAL=8
STEP_CURRENT=0
LOG_FILE="/tmp/ai-sbc-install.log"
SUDO=""

# ── Redirect all stderr to log file ──────────────────────────────────────────
exec 2>>"$LOG_FILE"

# ── Spinner ───────────────────────────────────────────────────────────────────
SPINNER_PID=""
SPINNER_FRAMES=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
SPINNER_DELAY=0.08

spinner_start() {
    local msg="$1"
    local i=0
    (while true; do
        printf "\r  ${CYAN}${SPINNER_FRAMES[$((i % 8))]}${RESET}  ${DIM}${msg}${RESET}   " >&2
        sleep "$SPINNER_DELAY"
        ((i++))
    done) &
    SPINNER_PID=$!
    disown "$SPINNER_PID" 2>/dev/null || true
}

spinner_stop() {
    if [ -n "$SPINNER_PID" ] && kill -0 "$SPINNER_PID" 2>/dev/null; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
    fi
    printf "\r%-60s\r" " "
}

# ── Progress bar ──────────────────────────────────────────────────────────────
progress_bar() {
    local current=$1 total=$2 label="$3"
    local width=40
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    local pct=$(( current * 100 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    printf "\r  ${CYAN}[${bar}]${RESET} ${BOLD}%3d%%${RESET}  ${DIM}%s${RESET}   " "$pct" "$label"
}

# ── Logging helpers ───────────────────────────────────────────────────────────
step_header() {
    ((STEP_CURRENT++))
    echo ""
    printf "  ${BG_DARK}${BOLD}${CYAN}  STEP %d/%d  ${RESET}${BOLD}  %s${RESET}\n" \
           "$STEP_CURRENT" "$STEPS_TOTAL" "$1"
    printf "  ${DIM}%s${RESET}\n" "$(printf '─%.0s' {1..55})"
}

ok()    { printf "  ${BGREEN}✓${RESET}  %s\n" "$1"; }
info()  { printf "  ${CYAN}·${RESET}  ${DIM}%s${RESET}\n" "$1"; }
warn()  { printf "  ${YELLOW}⚠${RESET}  ${YELLOW}%s${RESET}\n" "$1"; }
skip()  { printf "  ${BLUE}↷${RESET}  ${DIM}%s — already up to date${RESET}\n" "$1"; }
fail()  { echo ""; printf "  ${BRED}✗  FAILED: %s${RESET}\n" "$1";
          printf "  ${DIM}Check log: %s${RESET}\n" "$LOG_FILE"; exit 1; }

pkg_status() {
    # $1=name, $2=found_version, $3=required_version, $4=action (ok|install|update)
    local name="$1" ver="$2" req="$3" action="$4"
    case "$action" in
        ok)      printf "  ${BGREEN}✓${RESET}  %-22s ${DIM}%-14s${RESET} ${GREEN}meets requirement ≥%s${RESET}\n" "$name" "$ver" "$req" ;;
        install) printf "  ${YELLOW}+${RESET}  %-22s ${DIM}%-14s${RESET} ${YELLOW}installing...${RESET}\n" "$name" "not found" ;;
        update)  printf "  ${CYAN}↑${RESET}  %-22s ${DIM}%-14s${RESET} ${CYAN}updating → latest${RESET}\n" "$name" "$ver" ;;
        skip)    printf "  ${BLUE}↷${RESET}  %-22s ${DIM}%-14s${RESET} ${DIM}skipping (not needed)${RESET}\n" "$name" "$ver" ;;
    esac
}

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo ""
    printf "${BCYAN}  ================================================================${RESET}\n"
    printf "\n"
    printf "  ${BOLD}${BCYAN}  AI SBC Security${RESET}\n"
    printf "  ${BOLD}${WHITE}  Security · AI Edition${RESET}\n"
    printf "\n"
    printf "  ${DIM}  AI-powered security monitoring for SBCs & Linux${RESET}\n"
    printf "  ${DIM}  IDS  |  Anomaly AI  |  FIM  |  Vuln Scanner  |  Honeypot  |  2FA${RESET}\n"
    printf "  ${DIM}  github.com/fahimrahmanbooom/ai-sbc-security${RESET}\n"
    printf "\n"
    printf "${BCYAN}  ================================================================${RESET}\n"
    echo ""
}

# ── Version comparison ────────────────────────────────────────────────────────
version_gte() {
    # Returns 0 (true) if $1 >= $2 (semver comparison)
    local a="$1" b="$2"
    [ "$(printf '%s\n%s' "$a" "$b" | sort -V | head -1)" = "$b" ]
}

# ── Check single apt package ──────────────────────────────────────────────────
check_apt_pkg() {
    local pkg="$1"
    dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" && return 0 || return 1
}

# ── Detect system ─────────────────────────────────────────────────────────────
detect_system() {
    step_header "Detecting System"

    # Root/sudo
    if [ "$EUID" -ne 0 ]; then
        if sudo -n true 2>/dev/null; then
            SUDO="sudo"
            ok "Privilege escalation: sudo (passwordless)"
        elif sudo true 2>/dev/null; then
            SUDO="sudo"
            ok "Privilege escalation: sudo"
        else
            fail "Please run as root or configure sudo access"
        fi
    else
        ok "Running as root"
    fi

    # OS detection
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VER="${VERSION_ID:-?}"
        OS_PRETTY="${PRETTY_NAME:-Linux}"
    else
        fail "Cannot detect OS. Only Debian/Ubuntu-based systems supported."
    fi
    case "$OS_ID" in
        debian|ubuntu|raspbian|linuxmint|pop|kali|armbian) ok "OS: $OS_PRETTY" ;;
        *) warn "OS '$OS_ID' not officially tested. Proceeding..." ;;
    esac

    # Architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)   ok "Architecture: x86_64 (64-bit Intel/AMD)" ;;
        aarch64)  ok "Architecture: ARM64 (Raspberry Pi 4/5, Jetson, etc.)" ;;
        armv7l)   ok "Architecture: ARM32 (Raspberry Pi 3/Zero2W)" ;;
        armv6l)   warn "Architecture: ARM32v6 (Pi Zero) — minimal AI mode" ;;
        riscv64)  ok "Architecture: RISC-V 64 (experimental)" ;;
        *)        warn "Architecture: $ARCH — untested, continuing anyway" ;;
    esac

    # RAM
    TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    if   [ "$TOTAL_RAM_MB" -ge 2048 ]; then ok "RAM: ${TOTAL_RAM_MB}MB — excellent"
    elif [ "$TOTAL_RAM_MB" -ge 512 ];  then ok "RAM: ${TOTAL_RAM_MB}MB — sufficient"
    elif [ "$TOTAL_RAM_MB" -ge 256 ];  then warn "RAM: ${TOTAL_RAM_MB}MB — low, AI models will be minimal"
    else                                    warn "RAM: ${TOTAL_RAM_MB}MB — very low, may experience issues"
    fi

    # CPU cores
    CPU_CORES=$(nproc 2>/dev/null || echo 1)
    ok "CPU cores: $CPU_CORES"

    # Disk space
    DISK_AVAIL=$(df /opt --output=avail -BM 2>/dev/null | tail -1 | tr -d 'M' || echo 9999)
    if [ "$DISK_AVAIL" -ge 500 ]; then ok "Disk space: ${DISK_AVAIL}MB available"
    else warn "Disk space: only ${DISK_AVAIL}MB free — 500MB+ recommended"
    fi

    # Internet connectivity
    spinner_start "Checking internet connectivity..."
    if curl -s --connect-timeout 5 https://pypi.org > /dev/null 2>&1; then
        spinner_stop; ok "Internet: connected"
    else
        spinner_stop; warn "Internet: limited/offline — install may fail if packages are missing"
    fi
}

# ── System package check & install ────────────────────────────────────────────
install_system_deps() {
    step_header "System Dependencies"

    # Update apt cache (with cache age check — only update if >1 hour old)
    CACHE_AGE=9999
    if [ -f /var/cache/apt/pkgcache.bin ]; then
        CACHE_AGE=$(( ( $(date +%s) - $(stat -c %Y /var/cache/apt/pkgcache.bin) ) / 60 ))
    fi
    if [ "$CACHE_AGE" -gt 60 ]; then
        spinner_start "Refreshing package cache..."
        $SUDO apt-get update -qq >> "$LOG_FILE" 2>&1
        spinner_stop
        ok "Package cache refreshed"
    else
        skip "Package cache (fresh, ${CACHE_AGE}min old)"
    fi

    # ── APT packages to check/install ──────────────────────────────────────
    declare -A APT_PKGS=(
        ["python3"]="python3"
        ["python3-pip"]="python3-pip"
        ["python3-venv"]="python3-venv"
        ["python3-dev"]="python3-dev"
        ["gcc"]="gcc"
        ["g++"]="g++"
        ["git"]="git"
        ["curl"]="curl"
        ["wget"]="wget"
        ["libpcap-dev"]="libpcap-dev"
        ["libcap2-bin"]="libcap2-bin"
        ["net-tools"]="net-tools"
        ["iproute2"]="iproute2"
    )

    PKGS_TO_INSTALL=()
    for pkg in "${!APT_PKGS[@]}"; do
        if check_apt_pkg "$pkg"; then
            ver=$(dpkg -l "$pkg" 2>/dev/null | awk '/^ii/ {print $3}' | head -1)
            pkg_status "$pkg" "$ver" "-" "ok"
        else
            pkg_status "$pkg" "" "-" "install"
            PKGS_TO_INSTALL+=("$pkg")
        fi
    done

    if [ ${#PKGS_TO_INSTALL[@]} -gt 0 ]; then
        spinner_start "Installing ${#PKGS_TO_INSTALL[@]} system package(s)..."
        $SUDO apt-get install -y --no-install-recommends "${PKGS_TO_INSTALL[@]}" >> "$LOG_FILE" 2>&1 \
            || fail "apt-get install failed — check $LOG_FILE"
        spinner_stop
        ok "System packages installed"
    else
        ok "All system packages already present"
    fi
}

# ── Python version check ──────────────────────────────────────────────────────
check_python() {
    step_header "Python Runtime"

    # Find best Python
    PYTHON_BIN=""
    for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
        if command -v "$candidate" &>/dev/null; then
            PYTHON_BIN=$(command -v "$candidate")
            break
        fi
    done
    [ -z "$PYTHON_BIN" ] && fail "Python 3.9+ not found"

    PY_VER=$("$PYTHON_BIN" --version 2>&1 | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

    if [ "$PY_MAJOR" -lt 3 ] || [ "$PY_MINOR" -lt 9 ]; then
        fail "Python 3.9+ required. Found $PY_VER. Please upgrade."
    fi
    pkg_status "python3" "$PY_VER" "3.9" "ok"
    ok "Using: $PYTHON_BIN"

    # pip
    PIP_VER=$("$PYTHON_BIN" -m pip --version 2>/dev/null | awk '{print $2}' || echo "not found")
    if [ "$PIP_VER" = "not found" ]; then
        spinner_start "Installing pip..."
        $SUDO apt-get install -y python3-pip >> "$LOG_FILE" 2>&1
        spinner_stop
        ok "pip installed"
    else
        pkg_status "pip" "$PIP_VER" "21.0" "ok"
    fi
}

# ── Node.js check ─────────────────────────────────────────────────────────────
check_nodejs() {
    step_header "Node.js (Frontend Build)"

    NODE_MIN="16"
    NODE_VER=$(node --version 2>/dev/null | tr -d 'v' || echo "")
    NPM_VER=$(npm --version 2>/dev/null || echo "")

    if [ -z "$NODE_VER" ] || ! version_gte "$NODE_VER" "$NODE_MIN.0.0"; then
        if [ -n "$NODE_VER" ]; then
            pkg_status "nodejs" "v$NODE_VER" "$NODE_MIN" "update"
            info "Upgrading Node.js to v20 LTS..."
        else
            pkg_status "nodejs" "not found" "$NODE_MIN" "install"
            info "Installing Node.js v20 LTS..."
        fi

        spinner_start "Fetching NodeSource setup script..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO -E bash - >> "$LOG_FILE" 2>&1 \
            || fail "Failed to add NodeSource repo"
        spinner_stop

        spinner_start "Installing Node.js..."
        $SUDO apt-get install -y nodejs >> "$LOG_FILE" 2>&1 || fail "nodejs install failed"
        spinner_stop

        NODE_VER=$(node --version 2>/dev/null | tr -d 'v' || echo "?")
        NPM_VER=$(npm --version 2>/dev/null || echo "?")
        ok "Node.js v$NODE_VER installed"
        ok "npm v$NPM_VER installed"
    else
        pkg_status "nodejs" "v$NODE_VER" "$NODE_MIN" "ok"
        pkg_status "npm" "v$NPM_VER" "8" "ok"
    fi
}

# ── Download sources ──────────────────────────────────────────────────────────
install_sources() {
    step_header "Installing Source Files"

    $SUDO mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$DATA_DIR/models" "$CONFIG_DIR"

    # Detect install context
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo ".")"

    if [ -f "$SCRIPT_DIR/backend/main.py" ]; then
        info "Local source detected — copying files..."
        spinner_start "Copying source files..."
        $SUDO cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/" >> "$LOG_FILE" 2>&1
        spinner_stop
        ok "Source files copied from: $SCRIPT_DIR"
    elif [ -d "$INSTALL_DIR/.git" ]; then
        info "Existing install detected — pulling latest..."
        spinner_start "Pulling updates from GitHub..."
        $SUDO git -C "$INSTALL_DIR" pull --quiet >> "$LOG_FILE" 2>&1 \
            || warn "git pull failed — using existing files"
        spinner_stop
        ok "Source files updated"
    else
        info "Cloning from GitHub: $REPO_URL"
        spinner_start "Cloning repository..."
        $SUDO git clone --depth=1 "$REPO_URL" "$INSTALL_DIR/" >> "$LOG_FILE" 2>&1 \
            || fail "Git clone failed. Check internet connectivity."
        spinner_stop
        ok "Repository cloned to $INSTALL_DIR"
    fi

    # Set permissions
    $SUDO chown -R root:root "$INSTALL_DIR" >> "$LOG_FILE" 2>&1 || true
    $SUDO chmod +x "$INSTALL_DIR/install.sh" 2>/dev/null || true
    ok "Permissions configured"
}

# ── Python virtual environment + packages ─────────────────────────────────────
setup_python_env() {
    step_header "Python Packages"

    VENV_DIR="$INSTALL_DIR/venv"
    VENV_PY="$VENV_DIR/bin/python3"
    VENV_PIP="$VENV_DIR/bin/pip"

    # Create venv if needed
    if [ ! -f "$VENV_PY" ]; then
        spinner_start "Creating Python virtual environment..."
        $SUDO "$PYTHON_BIN" -m venv "$VENV_DIR" >> "$LOG_FILE" 2>&1 || fail "venv creation failed"
        spinner_stop
        ok "Virtual environment created"
    else
        EXISTING_VER=$("$VENV_PY" --version 2>&1 | awk '{print $2}')
        skip "Virtual environment ($EXISTING_VER)"
    fi

    # Upgrade pip
    spinner_start "Upgrading pip..."
    $SUDO "$VENV_PIP" install --upgrade pip setuptools wheel --quiet >> "$LOG_FILE" 2>&1
    spinner_stop
    PIP_VER=$("$VENV_PIP" --version | awk '{print $2}')
    ok "pip $PIP_VER ready"

    # Install Python requirements with per-package progress display
    REQ_FILE="$INSTALL_DIR/requirements.txt"
    [ -f "$REQ_FILE" ] || fail "requirements.txt not found at $REQ_FILE"

    TOTAL_PKGS=$(grep -c '.' "$REQ_FILE" || echo 20)
    PKG_NUM=0

    info "Installing Python packages (${TOTAL_PKGS} packages)..."
    echo ""

    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and blank lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        ((PKG_NUM++))
        PKG_NAME=$(echo "$line" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1 | tr -d ' ')

        progress_bar "$PKG_NUM" "$TOTAL_PKGS" "$PKG_NAME"

        # Check if already installed with compatible version
        INSTALLED_VER=$("$VENV_PIP" show "$PKG_NAME" 2>/dev/null | awk '/^Version:/ {print $2}' || echo "")
        REQUIRED_VER=$(echo "$line" | grep -oP '==\K[\d.]+' || echo "")

        if [ -n "$INSTALLED_VER" ] && [ -n "$REQUIRED_VER" ] && version_gte "$INSTALLED_VER" "$REQUIRED_VER"; then
            : # Already installed
        else
            $SUDO "$VENV_PIP" install "$line" --quiet >> "$LOG_FILE" 2>&1 || {
                printf "\r%-70s\r" " "
                warn "Failed to install $PKG_NAME — continuing..."
            }
        fi
    done < "$REQ_FILE"

    printf "\r%-70s\r" " "
    ok "All Python packages ready ($PKG_NUM packages)"
}

# ── Build frontend ────────────────────────────────────────────────────────────
build_frontend() {
    step_header "Building Dashboard"

    FRONTEND_DIR="$INSTALL_DIR/frontend"
    STATIC_DIR="$INSTALL_DIR/backend/static"
    NODE_MODULES="$FRONTEND_DIR/node_modules"

    # Check if build is already up to date
    if [ -d "$STATIC_DIR" ] && [ -f "$STATIC_DIR/index.html" ]; then
        BUILD_AGE=$(( ( $(date +%s) - $(stat -c %Y "$STATIC_DIR/index.html" 2>/dev/null || echo 0) ) / 60 ))
        SRC_CHANGED=0
        # Check if any source files are newer than the build
        if find "$FRONTEND_DIR/src" -newer "$STATIC_DIR/index.html" 2>/dev/null | grep -q .; then
            SRC_CHANGED=1
        fi

        if [ "$SRC_CHANGED" -eq 0 ] && [ "$BUILD_AGE" -lt 1440 ]; then
            skip "Frontend build (unchanged, built ${BUILD_AGE}min ago)"
            return 0
        fi
        info "Source changes detected — rebuilding..."
    fi

    # npm install (only if needed)
    if [ ! -d "$NODE_MODULES" ] || \
       [ "$FRONTEND_DIR/package.json" -nt "$NODE_MODULES/.package-lock.json" ] 2>/dev/null; then
        spinner_start "Installing npm packages..."
        cd "$FRONTEND_DIR"
        $SUDO npm install --silent >> "$LOG_FILE" 2>&1 || fail "npm install failed"
        spinner_stop
        ok "npm packages installed"
    else
        skip "npm packages (node_modules current)"
    fi

    # Build
    spinner_start "Building React dashboard (this may take 30-60s on SBCs)..."
    cd "$FRONTEND_DIR"
    $SUDO npm run build >> "$LOG_FILE" 2>&1 || {
        spinner_stop
        warn "Frontend build failed — dashboard will run in API-only mode"
        return 0
    }
    spinner_stop

    $SUDO mkdir -p "$STATIC_DIR"
    $SUDO cp -r "$FRONTEND_DIR/dist/"* "$STATIC_DIR/"
    ok "Dashboard built and ready"
    ok "Static files → $STATIC_DIR"
}

# ── Configuration ─────────────────────────────────────────────────────────────
configure() {
    step_header "Configuration"

    # Generate new secret or keep existing
    if [ -f "$CONFIG_DIR/env" ] && grep -q 'SECRET_KEY=' "$CONFIG_DIR/env" 2>/dev/null; then
        EXISTING_KEY=$(grep 'SECRET_KEY=' "$CONFIG_DIR/env" | cut -d= -f2)
        if [ -n "$EXISTING_KEY" ] && [ "${#EXISTING_KEY}" -ge 32 ]; then
            skip "Secret key (keeping existing key)"
            SECRET_KEY="$EXISTING_KEY"
        else
            SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
            ok "Secret key regenerated"
        fi
    else
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        ok "Secret key generated"
    fi

    # Write/update config.yaml
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        $SUDO cp "$INSTALL_DIR/config/default.yaml" "$CONFIG_DIR/config.yaml"
        ok "Configuration file created: $CONFIG_DIR/config.yaml"
    else
        skip "Configuration file (keeping existing settings)"
    fi

    # Write/update env file
    $SUDO tee "$CONFIG_DIR/env" > /dev/null << EOF
SECRET_KEY=$SECRET_KEY
CONFIG_PATH=$CONFIG_DIR/config.yaml
DB_PATH=$DATA_DIR/db.sqlite
MODEL_PATH=$DATA_DIR/models
TZ=$(cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")
EOF
    $SUDO chmod 600 "$CONFIG_DIR/env"
    ok "Environment file secured (600): $CONFIG_DIR/env"

    # Data directory ownership
    $SUDO chown -R root:root "$DATA_DIR" 2>/dev/null || true
    ok "Data directory: $DATA_DIR"
}

# ── Capabilities & Service ────────────────────────────────────────────────────
install_service() {
    step_header "System Service"

    # Packet capture capability
    PYTHON_BIN_VENV="$INSTALL_DIR/venv/bin/python3"
    if $SUDO setcap 'cap_net_raw+ep cap_net_admin+ep' "$PYTHON_BIN_VENV" >> "$LOG_FILE" 2>&1; then
        ok "Packet capture capability (CAP_NET_RAW) set"
    else
        warn "Could not set packet capture capability — network monitoring limited"
    fi

    # Stop existing service if running
    if $SUDO systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping existing service for upgrade..."
        $SUDO systemctl stop "$SERVICE_NAME" >> "$LOG_FILE" 2>&1 || true
    fi

    # Write systemd unit
    $SUDO tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=AI SBC Security — AI-Powered Security Monitoring
Documentation=https://github.com/fahimrahmanbooom/ai-sbc-security
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_DIR}/env
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m uvicorn backend.main:app \\
    --host 0.0.0.0 \\
    --port ${DEFAULT_PORT} \\
    --workers 1 \\
    --log-level info
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_FOWNER
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_FOWNER
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF

    ok "systemd unit file written"

    $SUDO systemctl daemon-reload >> "$LOG_FILE" 2>&1
    $SUDO systemctl enable "$SERVICE_NAME" >> "$LOG_FILE" 2>&1
    ok "Service enabled (auto-start on boot)"

    spinner_start "Starting service..."
    $SUDO systemctl start "$SERVICE_NAME" >> "$LOG_FILE" 2>&1 || true
    sleep 3
    spinner_stop

    if $SUDO systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Service is running ✓"
    else
        warn "Service may not have started — check: journalctl -u $SERVICE_NAME -n 30"
    fi

    # Install aisbc CLI tool — copy the canonical script from the repo
    # (the repo's aisbc file is the single source of truth; no embedded copy)
    if [ -f "$INSTALL_DIR/aisbc" ]; then
        $SUDO cp "$INSTALL_DIR/aisbc" /usr/local/bin/aisbc
    else
        warn "aisbc script not found in repo — skipping CLI install"
    fi
    $SUDO chmod +x /usr/local/bin/aisbc
    ok "aisbc CLI installed — run 'aisbc -up' to update anytime"
}

# ── Final summary ─────────────────────────────────────────────────────────────
print_summary() {
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
    SVC_STATUS=$($SUDO systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "unknown")

    echo ""
    printf "${BGREEN}  ================================================================${RESET}\n"
    printf "\n"
    printf "  ${BGREEN}  [OK] AI SBC Security -- Installation Complete!${RESET}\n"
    printf "\n"
    printf "${BGREEN}  ================================================================${RESET}\n"
    printf "\n"

    printf "  Service status:   "
    if [ "$SVC_STATUS" = "active" ]; then
        printf "${BGREEN}RUNNING${RESET}\n"
    else
        printf "${YELLOW}NOT RUNNING -- check: journalctl -u $SERVICE_NAME -n 30${RESET}\n"
    fi

    printf "\n"
    printf "  ${BOLD}Dashboard URLs:${RESET}\n"
    printf "    ${BCYAN}http://${LOCAL_IP}:${DEFAULT_PORT}${RESET}\n"
    printf "    ${CYAN}http://localhost:${DEFAULT_PORT}${RESET}\n"
    printf "\n"
    printf "${BGREEN}  ----------------------------------------------------------------${RESET}\n"
    printf "\n"
    printf "  ${BOLD}First-time setup:${RESET}\n"
    printf "    1. Open the dashboard URL above in your browser\n"
    printf "    2. Register your admin account\n"
    printf "    3. Scan the 2FA QR code with your authenticator app\n"
    printf "    4. AI models begin training automatically\n"
    printf "\n"
    printf "${BGREEN}  ----------------------------------------------------------------${RESET}\n"
    printf "\n"
    printf "  ${BOLD}Useful commands:${RESET}\n"
    printf "    ${BCYAN}aisbc -up${RESET}       ${DIM}Update to latest version${RESET}\n"
    printf "    ${BCYAN}aisbc -r${RESET}        ${DIM}Restart the service${RESET}\n"
    printf "    ${BCYAN}aisbc -s${RESET}        ${DIM}Show service status${RESET}\n"
    printf "    ${BCYAN}aisbc -l${RESET}        ${DIM}Tail live logs${RESET}\n"
    printf "    ${DIM}sudo nano /etc/ai-sbc-security/config.yaml${RESET}\n"
    printf "    ${DIM}bash install.sh --uninstall${RESET}\n"
    printf "\n"
    printf "${BGREEN}  ================================================================${RESET}\n"
    printf "\n"
    printf "  ${DIM}Install log: %s${RESET}\n" "$LOG_FILE"
    echo ""
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    print_banner
    printf "  ${BRED}⚠  UNINSTALL AI SBC SECURITY${RESET}\n\n"
    printf "  ${DIM}This will remove the application and all its files.${RESET}\n\n"

    read -p "  Are you sure? [y/N] " -n 1 -r </dev/tty; echo ""
    [[ $REPLY =~ ^[Yy]$ ]] || { echo "  Cancelled."; exit 0; }

    spinner_start "Stopping service..."
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    spinner_stop; ok "Service stopped"

    sudo rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    sudo systemctl daemon-reload
    ok "systemd unit removed"

    sudo rm -rf "$INSTALL_DIR" "$CONFIG_DIR"
    ok "Application files removed"

    echo ""
    read -p "  Remove all monitoring data ($DATA_DIR)? [y/N] " -n 1 -r </dev/tty; echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && sudo rm -rf "$DATA_DIR" && ok "Data directory removed"

    printf "\n  ${BGREEN}AI SBC Security has been uninstalled.${RESET}\n\n"
    exit 0
}

# ── Main entry point ──────────────────────────────────────────────────────────
main() {
    # Handle flags
    case "${1:-}" in
        --uninstall|-u) uninstall ;;
        --help|-h)
            echo "Usage: $0 [--uninstall]"
            echo "  (no args)     Install / update AI SBC Security"
            echo "  --uninstall   Remove AI SBC Security"
            exit 0 ;;
    esac

    print_banner

    START_TIME=$(date +%s)
    > "$LOG_FILE"  # Clear log

    detect_system
    install_system_deps
    check_python
    check_nodejs
    install_sources
    setup_python_env
    build_frontend
    configure
    install_service

    END_TIME=$(date +%s)
    ELAPSED=$(( END_TIME - START_TIME ))

    echo ""
    ok "Installation completed in ${ELAPSED}s"

    print_summary
}

main "$@"
