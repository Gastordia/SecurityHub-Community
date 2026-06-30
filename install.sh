#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SecurityHub Community Edition — Installer
# ══════════════════════════════════════════════════════════════════════════════
# Supports: Ubuntu/Debian · RHEL/CentOS/AlmaLinux/Rocky · Fedora
#           Arch Linux · openSUSE · Alpine Linux · macOS (Homebrew)
#
# Usage:
#   bash install.sh                 # interactive
#   bash install.sh --non-interactive   # read everything from existing .env
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Terminal colours ──────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD='\033[1m'; DIM='\033[2m'; RED='\033[0;31m'; GREEN='\033[0;32m'
  YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

info()    { printf "${CYAN}  ▸ %s${NC}\n" "$*"; }
success() { printf "${GREEN}  ✔ %s${NC}\n" "$*"; }
warn()    { printf "${YELLOW}  ⚠ %s${NC}\n" "$*"; }
error()   { printf "${RED}  ✘ %s${NC}\n" "$*" >&2; }
die()     { error "$*"; exit 1; }
hr()      { printf "${DIM}%s${NC}\n" "──────────────────────────────────────────────────────────────────────────────"; }

# ── Error trap — fires on any unhandled command failure (set -e) ──────────────
_on_error() {
  local line="${1:-?}"
  printf "\n${RED}${BOLD}  ✘ Installer failed at line ${line}.${NC}\n"
  printf "  Check the output above for details.\n"
  printf "  Fix the issue then re-run: ${BOLD}bash install.sh${NC}\n\n"
}
trap '_on_error $LINENO' ERR

# ── WSL detection ─────────────────────────────────────────────────────────────
IS_WSL=false
if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null || \
   [[ -n "${WSL_DISTRO_NAME:-}" ]] || [[ -n "${WSLENV:-}" ]]; then
  IS_WSL=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
NON_INTERACTIVE=false
[[ "${1:-}" == "--non-interactive" ]] && NON_INTERACTIVE=true

# ── Helpers ───────────────────────────────────────────────────────────────────
prompt_val() {
  # Usage: prompt_val "Question" "default" [secret]  → sets $REPLY_VAL
  local question="$1" default="$2" is_secret="${3:-}"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then REPLY_VAL="$default"; return; fi
  if [[ -n "$is_secret" ]]; then
    printf "  ${BOLD}%s${NC}" "$question"
    [[ -n "$default" ]] && printf " ${DIM}[press Enter to auto-generate]${NC}"
    printf ": "
    read -rs REPLY_VAL || REPLY_VAL=""; echo
  else
    printf "  ${BOLD}%s${NC}" "$question"
    [[ -n "$default" ]] && printf " ${DIM}[${default}]${NC}"
    printf ": "
    read -r REPLY_VAL || REPLY_VAL=""
  fi
  if [[ -z "$REPLY_VAL" ]]; then REPLY_VAL="$default"; fi
}

prompt_yn() {
  # Usage: prompt_yn "Question" "y|n"  → returns 0 (yes) or 1 (no)
  local question="$1" default="${2:-y}"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then [[ "$default" == "y" ]] && return 0 || return 1; fi
  local hint; [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
  printf "  ${BOLD}%s${NC} ${DIM}[%s]${NC}: " "$question" "$hint"
  read -r _yn || _yn=""; _yn="${_yn:-$default}"
  [[ "${_yn,,}" == "y" || "${_yn,,}" == "yes" ]]
}

gen_secret()   { python3 -c "import secrets; print(secrets.token_urlsafe(50))" 2>/dev/null || \
                 openssl rand -base64 37 | tr -dc 'a-zA-Z0-9' | head -c50; }
gen_password() { python3 -c "
import secrets, string
a='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%'
print(''.join(secrets.choice(a) for _ in range(20)))" 2>/dev/null || \
                 openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c20; }

# ── Banner ────────────────────────────────────────────────────────────────────
[[ -t 1 ]] && clear
printf "\n${BOLD}${CYAN}"
cat <<'BANNER'
  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗██╗  ██╗██╗   ██╗██████╗
  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██║  ██║██║   ██║██╔══██╗
  ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ ███████║██║   ██║██████╔╝
  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  ██╔══██║██║   ██║██╔══██╗
  ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   ██║  ██║╚██████╔╝██████╔╝
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝
BANNER
printf "${NC}\n  ${BOLD}Community Edition — Installer${NC}\n\n"
hr

# ══════════════════════════════════════════════════════════════════════════════
# STEP 0 — Choose deployment mode
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[0/6] Deployment mode${NC}\n"
hr
printf "\n"
printf "  ${BOLD}1)${NC} Docker Compose  ${DIM}(recommended — installs Docker automatically, zero system config)${NC}\n"
printf "  ${BOLD}2)${NC} Bare-metal      ${DIM}(Python + Node + PostgreSQL + Nginx + systemd on this host)${NC}\n"
printf "\n"

DEPLOY_MODE="docker"
if [[ "$NON_INTERACTIVE" == "true" ]]; then
  [[ -n "${DEPLOY_MODE_OVERRIDE:-}" ]] && DEPLOY_MODE="$DEPLOY_MODE_OVERRIDE"
else
  while true; do
    printf "  ${BOLD}Choice${NC} ${DIM}[1]${NC}: "
    read -r _choice || _choice=""
    case "${_choice:-1}" in
      1|docker)    DEPLOY_MODE="docker";    break ;;
      2|baremetal|bare-metal|bare) DEPLOY_MODE="baremetal"; break ;;
      *) warn "Please enter 1 or 2." ;;
    esac
  done
fi
success "Deployment mode: ${BOLD}${DEPLOY_MODE}${NC}"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — OS detection
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[1/6] Detecting operating system${NC}\n"
hr

OS_TYPE=""; PKG_MANAGER=""
if [[ "$(uname -s)" == "Darwin" ]]; then
  OS_TYPE="macos"; PKG_MANAGER="brew"
elif [[ -f /etc/os-release ]]; then
  . /etc/os-release
  case "${ID_LIKE:-}${ID}" in
    *debian*|*ubuntu*) OS_TYPE="debian";  PKG_MANAGER="apt"    ;;
    *rhel*|*centos*|*almalinux*|*rocky*) OS_TYPE="rhel"; PKG_MANAGER="dnf" ;;
    fedora*)           OS_TYPE="fedora";  PKG_MANAGER="dnf"    ;;
    arch*|manjaro*)    OS_TYPE="arch";    PKG_MANAGER="pacman" ;;
    *suse*|opensuse*)  OS_TYPE="suse";    PKG_MANAGER="zypper" ;;
    alpine*)           OS_TYPE="alpine";  PKG_MANAGER="apk"    ;;
    *)                 OS_TYPE="unknown"                        ;;
  esac
else
  OS_TYPE="unknown"
fi
success "OS: ${BOLD}${OS_TYPE}${NC} (${PRETTY_NAME:-$(uname -sr)})"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Install runtime (Docker OR system packages)
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[2/6] Installing runtime${NC}\n"
hr

DOCKER_CMD=""; COMPOSE_CMD=""

install_docker() {
  case "$OS_TYPE" in
    debian)
      info "Installing Docker via official apt repository..."
      sudo apt-get update -qq
      sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release
      sudo install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      sudo chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
$(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
      sudo apt-get update -qq
      sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      ;;
    rhel)
      info "Installing Docker (RHEL/CentOS)..."
      sudo dnf -y -q install dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      sudo dnf -y -q install docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      sudo systemctl enable --now docker
      ;;
    fedora)
      info "Installing Docker (Fedora)..."
      sudo dnf -y -q install dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      sudo dnf -y -q install docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      sudo systemctl enable --now docker
      ;;
    arch)
      sudo pacman -Sy --noconfirm --quiet docker docker-compose
      sudo systemctl enable --now docker
      ;;
    suse)
      sudo zypper -q install -y docker docker-compose
      sudo systemctl enable --now docker
      ;;
    alpine)
      sudo apk add --quiet docker docker-compose
      sudo rc-update add docker default && sudo service docker start
      ;;
    macos)
      command -v brew &>/dev/null || die "Homebrew required. Install from https://brew.sh then re-run."
      brew install --cask docker
      die "Docker Desktop installed. Launch it, wait for it to start, then re-run this script."
      ;;
    *) die "Cannot auto-install Docker on '${OS_TYPE}'. Install it manually then re-run." ;;
  esac
}

install_node() {
  # Ensure Node.js 18+. Use NodeSource for Debian/RHEL families; package manager otherwise.
  if command -v node &>/dev/null; then
    local ver; ver="$(node -e 'process.stdout.write(process.versions.node)' 2>/dev/null)"
    local major="${ver%%.*}"
    if (( major >= 18 )); then success "Node.js ${ver} found."; return; fi
    warn "Node.js ${ver} is too old (need 18+). Upgrading..."
  fi
  case "$OS_TYPE" in
    debian)
      info "Installing Node.js 20 via NodeSource..."
      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null
      sudo apt-get install -y -qq nodejs
      ;;
    rhel|fedora)
      info "Installing Node.js 20 via NodeSource..."
      curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash - >/dev/null
      sudo "$PKG_MANAGER" -y -q install nodejs
      ;;
    arch)   sudo pacman -Sy --noconfirm --quiet nodejs npm ;;
    suse)   sudo zypper -q install -y nodejs20 npm20 ;;
    alpine) sudo apk add --quiet nodejs npm ;;
    macos)  brew install node ;;
    *)      die "Cannot auto-install Node.js on '${OS_TYPE}'. Install Node 18+ manually then re-run." ;;
  esac
  success "Node.js $(node --version) installed."
}

install_system_deps_baremetal() {
  info "Installing Python, PostgreSQL, Nginx, and WeasyPrint system libraries..."
  case "$OS_TYPE" in
    debian)
      sudo apt-get update -qq
      sudo apt-get install -y -qq \
        python3 python3-pip python3-venv python3-dev \
        build-essential curl libpq-dev \
        postgresql postgresql-client \
        nginx \
        libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
        libxml2-dev libxslt1-dev
      ;;
    rhel)
      sudo dnf -y -q install epel-release
      sudo dnf -y -q install \
        python3 python3-pip python3-devel \
        gcc gcc-c++ make curl postgresql-devel \
        postgresql-server postgresql \
        nginx \
        cairo cairo-devel pango pango-devel \
        gdk-pixbuf2 libffi-devel libxml2-devel libxslt-devel
      # Initialize PostgreSQL cluster (RHEL doesn't do it automatically)
      sudo postgresql-setup --initdb 2>/dev/null || true
      sudo systemctl enable --now postgresql
      ;;
    fedora)
      sudo dnf -y -q install \
        python3 python3-pip python3-devel \
        gcc gcc-c++ make curl postgresql-devel \
        postgresql-server postgresql \
        nginx \
        cairo cairo-devel pango pango-devel \
        gdk-pixbuf2 libffi-devel libxml2-devel libxslt-devel
      sudo postgresql-setup --initdb 2>/dev/null || true
      sudo systemctl enable --now postgresql
      ;;
    arch)
      sudo pacman -Sy --noconfirm --quiet \
        python python-pip \
        base-devel curl postgresql \
        nginx \
        cairo pango gdk-pixbuf2 libffi
      # Arch: init postgres cluster as postgres user
      sudo -u postgres initdb -D /var/lib/postgres/data 2>/dev/null || true
      sudo systemctl enable --now postgresql
      ;;
    suse)
      sudo zypper -q install -y \
        python311 python311-pip \
        gcc make curl postgresql-devel \
        postgresql postgresql-server \
        nginx \
        cairo-devel pango-devel \
        gdk-pixbuf libffi-devel libxml2-devel libxslt-devel
      sudo systemctl enable --now postgresql
      ;;
    alpine)
      sudo apk add --quiet \
        python3 py3-pip python3-dev \
        build-base curl postgresql-dev \
        postgresql nginx \
        cairo pango gdk-pixbuf libffi-dev \
        libxml2-dev libxslt-dev
      sudo rc-update add postgresql default && sudo service postgresql start
      ;;
    macos)
      command -v brew &>/dev/null || die "Homebrew required. Install from https://brew.sh then re-run."
      brew install python@3.11 postgresql@16 nginx cairo pango gdk-pixbuf libffi
      brew services start postgresql@16
      ;;
    *) die "Cannot auto-install system dependencies on '${OS_TYPE}'. Install them manually." ;;
  esac
  success "System packages installed."
}

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  # ── Docker checks ────────────────────────────────────────────────────────
  if command -v docker &>/dev/null; then
    DOCKER_CMD="docker"
    success "Docker found: $(docker --version 2>&1 | head -1)"
  else
    warn "Docker not found — installing..."
    install_docker
    DOCKER_CMD="docker"
  fi

  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
    success "Docker Compose plugin: $(docker compose version --short 2>&1)"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    success "docker-compose: $(docker-compose --version 2>&1 | head -1)"
  else
    case "$OS_TYPE" in
      debian) sudo apt-get install -y -qq docker-compose-plugin; COMPOSE_CMD="docker compose" ;;
      rhel|fedora) sudo "$PKG_MANAGER" -y -q install docker-compose-plugin; COMPOSE_CMD="docker compose" ;;
      *) die "Docker Compose not found. Install it and re-run." ;;
    esac
  fi

  if [[ "$OS_TYPE" != "macos" ]] && ! groups 2>/dev/null | grep -q docker; then
    warn "Adding ${USER} to docker group (takes effect after next login)."
    sudo usermod -aG docker "$USER" 2>/dev/null || true
  fi

  if ! $DOCKER_CMD info &>/dev/null 2>&1; then
    if [[ "$IS_WSL" == "true" ]]; then
      printf "\n"
      error "Docker daemon is not running."
      printf "\n  ${BOLD}WSL detected.${NC} Docker needs to be running. Fix this with one of:\n\n"
      printf "  ${BOLD}Option 1 — Docker Desktop (recommended):${NC}\n"
      printf "    Open Docker Desktop on Windows → Settings → Resources\n"
      printf "    → WSL Integration → enable for ${BOLD}${WSL_DISTRO_NAME:-this distro}${NC}\n"
      printf "    Then restart Docker Desktop and re-run this script.\n\n"
      printf "  ${BOLD}Option 2 — Docker Engine inside WSL:${NC}\n"
      printf "    ${DIM}sudo service docker start${NC}\n"
      printf "    Then re-run: ${BOLD}bash install.sh${NC}\n\n"
      exit 1
    fi
    info "Starting Docker daemon..."
    if command -v systemctl &>/dev/null && systemctl list-units --type=service &>/dev/null 2>&1; then
      sudo systemctl start docker 2>/dev/null || true
    elif command -v service &>/dev/null; then
      sudo service docker start 2>/dev/null || true
    fi
    sleep 3
    $DOCKER_CMD info &>/dev/null 2>&1 || \
      die "Docker daemon is not running. Start it ('sudo systemctl start docker' or 'sudo service docker start') then re-run."
  fi
  success "Docker is running."

else
  # ── Bare-metal: system packages + Node.js ────────────────────────────────
  install_system_deps_baremetal
  install_node
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Configuration prompts (shared for both modes)
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[3/6] Configuration${NC}\n"
hr

# Load existing .env as defaults if it exists
if [[ -f "$ENV_FILE" ]]; then
  warn "Existing .env found — loading as defaults."
  set -a; . "$ENV_FILE" 2>/dev/null || true; set +a
fi

# ── Quick vs Custom setup ─────────────────────────────────────────────────────
printf "\n"
printf "  ${BOLD}1) Quick setup${NC}   ${DIM}— just credentials + domain, everything else is auto-configured${NC}\n"
printf "  ${BOLD}2) Custom setup${NC}  ${DIM}— step through all options (database names, Redis, SMTP, etc.)${NC}\n"
printf "\n"

SETUP_MODE="quick"
if [[ "$NON_INTERACTIVE" != "true" ]]; then
  while true; do
    printf "  ${BOLD}Choice${NC} ${DIM}[1]${NC}: "
    read -r _sc || _sc=""
    case "${_sc:-1}" in
      1|quick)  SETUP_MODE="quick";  break ;;
      2|custom) SETUP_MODE="custom"; break ;;
      *) warn "Please enter 1 or 2." ;;
    esac
  done
fi
printf "\n"

# ── Helper: prompt for a password with confirm + auto-generate fallback ────────
# Usage: prompt_password "Label" "existing_value_or_empty"
# Sets $PASS_RESULT
prompt_password() {
  local label="$1" existing="${2:-}"
  if [[ -n "$existing" ]]; then
    PASS_RESULT="$existing"; info "Keeping existing ${label}."; return
  fi
  while true; do
    prompt_val "${label}" "" "secret"
    local p1="$REPLY_VAL"
    if [[ -z "$p1" ]]; then
      PASS_RESULT="$(gen_password)"
      success "${label} auto-generated."
      return
    fi
    prompt_val "Confirm ${label}" "" "secret"
    local p2="$REPLY_VAL"
    if [[ "$p1" == "$p2" ]]; then PASS_RESULT="$p1"; return; fi
    warn "Passwords do not match — try again."
  done
}

# ── Login credentials (always asked) ─────────────────────────────────────────
printf "  ${BOLD}── Login credentials ────────────────────────────────────────${NC}\n"
printf "  ${DIM}What you will use to sign into SecurityHub.${NC}\n\n"

prompt_val "Username" "${SETUP_USERNAME:-admin}";              ADMIN_USER="$REPLY_VAL"
prompt_val "Email"    "${SETUP_EMAIL:-admin@securityhub.local}"; ADMIN_EMAIL="$REPLY_VAL"

_existing_admin=""
[[ -n "${SETUP_PASSWORD:-}" ]] && _existing_admin="$SETUP_PASSWORD"
prompt_password "Admin password" "$_existing_admin"
ADMIN_PASS="$PASS_RESULT"

ADMIN_FULL_NAME="${SETUP_FULL_NAME:-${ADMIN_USER}}"

# ── Network (always asked) ────────────────────────────────────────────────────
printf "\n  ${BOLD}── Network ──────────────────────────────────────────────────${NC}\n"

prompt_val "Domain or public IP" "${DOMAIN:-yourdomain.com}"; DOMAIN="$REPLY_VAL"

if prompt_yn "Is HTTPS already configured for this domain?" "y"; then
  SCHEME="https"; COOKIE_SECURE="True"
else
  SCHEME="http"; COOKIE_SECURE="False"
  warn "Running without HTTPS. Set AUTH_COOKIE_SECURE=True once you add TLS."
fi
BASE_URL="${SCHEME}://${DOMAIN}"

# ── Secrets — always auto-generated (not prompted) ────────────────────────────
if [[ -n "${SECRET_KEY:-}" && "$SECRET_KEY" != "CHANGE_ME_replace_with_a_long_random_secret" ]]; then
  GENERATED_KEY="$SECRET_KEY"
  info "Keeping existing Django / JWT secret key."
else
  GENERATED_KEY="$(gen_secret)"
  info "Django / JWT secret key: auto-generated (64 chars)."
fi

# ── Database defaults (used in quick mode) ────────────────────────────────────
DB_USER="${POSTGRES_USER:-securityhub_user}"
DB_NAME="${POSTGRES_DB:-securityhub}"
DB_HOST_DEFAULT="$([[ "$DEPLOY_MODE" == "docker" ]] && echo "postgres" || echo "127.0.0.1")"
DB_HOST="$DB_HOST_DEFAULT"

# Database password
_existing_db=""
[[ -n "${POSTGRES_PASSWORD:-}" && "${POSTGRES_PASSWORD}" != "CHANGE_ME_db_password" ]] && _existing_db="$POSTGRES_PASSWORD"

if [[ "$SETUP_MODE" == "quick" ]]; then
  if [[ -n "$_existing_db" ]]; then
    DB_PASS="$_existing_db"; info "Keeping existing database password."
  else
    DB_PASS="$(gen_password)"; info "Database password: auto-generated."
  fi
else
  # Custom: ask for everything
  printf "\n  ${BOLD}── Database (PostgreSQL) ────────────────────────────────────${NC}\n"
  prompt_val "Database user" "$DB_USER";  DB_USER="$REPLY_VAL"
  prompt_val "Database name" "$DB_NAME";  DB_NAME="$REPLY_VAL"
  prompt_password "Database password" "$_existing_db"; DB_PASS="$PASS_RESULT"
fi

# ── Site defaults (quick = use defaults; custom = ask) ────────────────────────
SITE_NAME_VAL="${SITE_NAME:-SecurityHub}"
TZ_VAL="${USER_TIME_ZONE:-UTC}"

if [[ "$SETUP_MODE" == "custom" ]]; then
  printf "\n  ${BOLD}── Site ─────────────────────────────────────────────────────${NC}\n"
  prompt_val "Site name"                                 "$SITE_NAME_VAL"; SITE_NAME_VAL="$REPLY_VAL"
  prompt_val "Timezone (IANA, e.g. UTC / Europe/Paris)" "$TZ_VAL";        TZ_VAL="$REPLY_VAL"
fi

# ── JWT token lifetimes (custom only) ─────────────────────────────────────────
JWT_ACCESS_MINUTES="${JWT_ACCESS_TOKEN_LIFETIME_MINUTES:-30}"
JWT_REFRESH_DAYS="${JWT_REFRESH_TOKEN_LIFETIME_DAYS:-7}"

if [[ "$SETUP_MODE" == "custom" ]]; then
  printf "\n  ${BOLD}── JWT token lifetimes ──────────────────────────────────────${NC}\n"
  prompt_val "Access token lifetime (minutes)"  "$JWT_ACCESS_MINUTES";  JWT_ACCESS_MINUTES="$REPLY_VAL"
  prompt_val "Refresh token lifetime (days)"    "$JWT_REFRESH_DAYS";    JWT_REFRESH_DAYS="$REPLY_VAL"
fi

# ── Optional features (custom only; quick = disabled) ─────────────────────────
REDIS_URL_VAL="${REDIS_URL:-}"
REDIS_PASS_VAL="${REDIS_PASSWORD:-}"
USE_EMAIL_VAL="False"
EMAIL_HOST_VAL="${EMAIL_HOST:-smtp.example.com}"; EMAIL_PORT_VAL="${EMAIL_PORT:-587}"
EMAIL_TLS_VAL="${EMAIL_USE_TLS:-True}";           EMAIL_USER_VAL="${EMAIL_HOST_USER:-}"
EMAIL_PASS_VAL="${EMAIL_HOST_PASSWORD:-}"

if [[ "$SETUP_MODE" == "custom" ]]; then
  printf "\n  ${BOLD}── Optional features ────────────────────────────────────────${NC}\n"

  if prompt_yn "Enable Redis cache? (recommended for multiple workers)" "n"; then
    _existing_redis=""
    [[ -n "${REDIS_PASSWORD:-}" && "${REDIS_PASSWORD}" != "CHANGE_ME_redis_password" ]] && _existing_redis="$REDIS_PASSWORD"
    prompt_password "Redis password" "$_existing_redis"; REDIS_PASS_VAL="$PASS_RESULT"
    if [[ "$DEPLOY_MODE" == "docker" ]]; then
      REDIS_URL_VAL="redis://:${REDIS_PASS_VAL}@cache:6379/"
    else
      REDIS_URL_VAL="redis://:${REDIS_PASS_VAL}@127.0.0.1:6379/"
      warn "Install Redis manually (redis-server) and start it before launching the app."
    fi
    success "Redis enabled."
  else
    REDIS_PASS_VAL="$(gen_password)"  # store a safe default even if unused
    info "Using in-memory cache."
  fi

  if prompt_yn "Configure outbound email (SMTP)?" "n"; then
    USE_EMAIL_VAL="True"
    prompt_val "SMTP host"     "$EMAIL_HOST_VAL"; EMAIL_HOST_VAL="$REPLY_VAL"
    prompt_val "SMTP port"     "$EMAIL_PORT_VAL"; EMAIL_PORT_VAL="$REPLY_VAL"
    prompt_val "SMTP username" "$EMAIL_USER_VAL"; EMAIL_USER_VAL="$REPLY_VAL"
    prompt_password "SMTP password" "$EMAIL_PASS_VAL"; EMAIL_PASS_VAL="$PASS_RESULT"
    success "Email enabled."
  else
    info "Email disabled (invitation links shared manually)."
  fi
else
  # Quick mode: generate a safe Redis password even though Redis is off,
  # so if the user enables it later the .env already has a real secret.
  [[ -z "$REDIS_PASS_VAL" ]] && REDIS_PASS_VAL="$(gen_password)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Write .env
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[4/6] Writing .env${NC}\n"
hr

# Mode-specific values
if [[ "$DEPLOY_MODE" == "docker" ]]; then
  USE_DOCKER_VAL="True"
  INTERNAL_URL="https://nginx"
  WHITELIST_VAL='["https://nginx"]'
else
  USE_DOCKER_VAL="False"
  INTERNAL_URL="http://127.0.0.1"
  WHITELIST_VAL='["http://127.0.0.1"]'
fi

ALLOWED_HOST_VAL='["'"$DOMAIN"'","localhost","127.0.0.1"]'

# Build CORS/CSRF origin list.
# In Docker mode the browser hits nginx on the mapped port (3000→HTTP redirect,
# 8443→HTTPS). Always include port-qualified localhost URLs so local/WSL installs
# work without CORS errors, even when the user typed a bare hostname.
if [[ "$DEPLOY_MODE" == "docker" ]]; then
  CORS_ORIGINS="${BASE_URL},https://localhost:8443,http://localhost:3000"
  # If the user's domain is not localhost, that's already in BASE_URL; nothing extra needed.
else
  CORS_ORIGINS="${BASE_URL}"
fi

cat > "$ENV_FILE" <<EOF
# SecurityHub Community Edition — generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# DO NOT commit this file — it contains secrets.
# To reconfigure, run:  bash install.sh

# ── Deployment mode ───────────────────────────────────────────────────────────
USE_DOCKER=${USE_DOCKER_VAL}
INTERNAL_BASE_URL=${INTERNAL_URL}

# ── Django core ───────────────────────────────────────────────────────────────
SECRET_KEY=${GENERATED_KEY}
DEBUG=False
ALLOWED_HOST=${ALLOWED_HOST_VAL}
CORS_ALLOWED_ORIGINS=${CORS_ORIGINS}
CSRF_TRUSTED_ORIGINS=${CORS_ORIGINS}
WHITELIST_IP=${WHITELIST_VAL}
FRONTEND_URL=${BASE_URL}
USER_TIME_ZONE=${TZ_VAL}

# ── Database ──────────────────────────────────────────────────────────────────
POSTGRES_USER=${DB_USER}
POSTGRES_PASSWORD=${DB_PASS}
POSTGRES_DB=${DB_NAME}
POSTGRES_HOST=${DB_HOST}
POSTGRES_PORT=5432

# ── Cache ──────────────────────────────────────────────────────────────────────
REDIS_PASSWORD=${REDIS_PASS_VAL}
REDIS_URL=${REDIS_URL_VAL}
CACHE_TIMEOUT_SECONDS=900

# ── Storage ────────────────────────────────────────────────────────────────────
USE_S3=False
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_STORAGE_BUCKET_NAME=
AWS_S3_REGION_NAME=
AWS_S3_CUSTOM_DOMAIN=
AWS_S3_ENDPOINT_URL=

# ── Auth & JWT ─────────────────────────────────────────────────────────────────
AUTH_COOKIE_SECURE=${COOKIE_SECURE}
JWT_ACCESS_TOKEN_LIFETIME_MINUTES=${JWT_ACCESS_MINUTES}
JWT_REFRESH_TOKEN_LIFETIME_DAYS=${JWT_REFRESH_DAYS}
PASSWORD_MIN_LENGTH=10

# ── Email ──────────────────────────────────────────────────────────────────────
USE_EMAIL=${USE_EMAIL_VAL}
EMAIL_HOST=${EMAIL_HOST_VAL}
EMAIL_PORT=${EMAIL_PORT_VAL}
EMAIL_USE_TLS=${EMAIL_TLS_VAL}
EMAIL_HOST_USER=${EMAIL_USER_VAL}
EMAIL_HOST_PASSWORD=${EMAIL_PASS_VAL}
DEFAULT_FROM_EMAIL=

# ── VulnDB / reference data sync ──────────────────────────────────────────────
VULNDB_GITHUB_URL=
PROJECT_TYPES_GITHUB_URL=
REPORT_STANDARDS_GITHUB_URL=
CWE_DATA_GITHUB_URL=https://raw.githubusercontent.com/APTRS/APTRS-CWE/main/cwe.json

# ── Branding ───────────────────────────────────────────────────────────────────
SITE_NAME=${SITE_NAME_VAL}
SITE_SUPPORT_EMAIL=support@securityhub.community

# ── Admin account (first-time setup) ──────────────────────────────────────────
SETUP_USERNAME=${ADMIN_USER}
SETUP_EMAIL=${ADMIN_EMAIL}
SETUP_FULL_NAME=${ADMIN_FULL_NAME}
SETUP_POSITION=Security Engineer
SETUP_COMPANY_NAME=${SITE_NAME_VAL}
SETUP_PASSWORD=${ADMIN_PASS}

# ── Advanced tuning ────────────────────────────────────────────────────────────
MAX_UPLOAD_MB_IMAGE=10
MAX_UPLOAD_MB_DOCUMENT=50
MAX_UPLOAD_MB_SCAN=100
MAX_UPLOAD_MB_ARCHIVE=200
MAX_UPLOAD_MB_DEFAULT=50
PAGINATION_STANDARD_PAGE_SIZE=25
PAGINATION_STANDARD_MAX_PAGE_SIZE=100
PAGINATION_LARGE_PAGE_SIZE=100
PAGINATION_LARGE_MAX_PAGE_SIZE=500
PAGINATION_SMALL_PAGE_SIZE=10
PAGINATION_SMALL_MAX_PAGE_SIZE=50
PAGINATION_CURSOR_DEFAULT_LIMIT=25
PAGINATION_CURSOR_MAX_LIMIT=100
THROTTLE_RATE_ANON=50/minute
THROTTLE_RATE_USER=200/minute
THROTTLE_RATE_LOGIN=5/minute
THROTTLE_RATE_FILE_UPLOAD=10/minute
THROTTLE_RATE_SEARCH=30/minute
THROTTLE_RATE_ADMIN=500/minute
THROTTLE_RATE_BURST=100/minute
EOF

chmod 600 "$ENV_FILE"
success ".env written (permissions: 600)."

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Start / build the application
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[5/6] Starting SecurityHub${NC}\n"
hr
cd "$SCRIPT_DIR"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  # ── Docker path ───────────────────────────────────────────────────────────
  export DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1

  info "Pulling base images..."
  $COMPOSE_CMD pull --quiet 2>/dev/null || true
  info "Building application images..."
  $COMPOSE_CMD build --quiet
  info "Starting services..."
  $COMPOSE_CMD up -d

  info "Waiting for backend to become healthy (up to 3 min)..."
  WAIT=0; MAX=180; BACKEND_HEALTHY=false
  SH_CONTAINER_ID=""
  until [[ $WAIT -ge $MAX ]]; do
    SH_CONTAINER_ID="$($COMPOSE_CMD ps -q securityhub 2>/dev/null | head -1)"
    if [[ -n "$SH_CONTAINER_ID" ]]; then
      STATUS="$($DOCKER_CMD inspect --format='{{.State.Health.Status}}' "$SH_CONTAINER_ID" 2>/dev/null || true)"
      if [[ "$STATUS" == "healthy" ]]; then
        BACKEND_HEALTHY=true; break
      elif [[ "$STATUS" == "unhealthy" ]]; then
        printf "                              \r"
        error "Backend container is unhealthy."
        printf "\n  ${BOLD}Diagnose with:${NC}\n"
        printf "    ${DIM}${COMPOSE_CMD} logs securityhub${NC}\n\n"
        die "Startup failed."
      fi
    fi
    printf "    ${DIM}waiting... (%ds / %ds)${NC}\r" "$WAIT" "$MAX"
    sleep 5; (( WAIT += 5 ))
  done
  printf "                                          \r"
  if [[ "$BACKEND_HEALTHY" != "true" ]]; then
    error "Backend did not become healthy within ${MAX}s."
    printf "\n  ${BOLD}Diagnose with:${NC}\n"
    printf "    ${DIM}${COMPOSE_CMD} logs securityhub${NC}\n"
    printf "    ${DIM}${COMPOSE_CMD} ps${NC}\n\n"
    die "Startup timed out."
  fi
  success "All containers are healthy."

else
  # ── Bare-metal path ───────────────────────────────────────────────────────

  # -- PostgreSQL: create database and user ---------------------------------
  info "Setting up PostgreSQL database..."
  PG_SETUP_SQL="
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE USER \"${DB_USER}\" WITH PASSWORD '${DB_PASS}';
  ELSE
    ALTER USER \"${DB_USER}\" WITH PASSWORD '${DB_PASS}';
  END IF;
END\$\$;
CREATE DATABASE \"${DB_NAME}\" OWNER \"${DB_USER}\" ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8' TEMPLATE template0;
"
  # Run as postgres superuser; ignore "database already exists"
  sudo -u postgres psql -c "
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE USER \"${DB_USER}\" WITH PASSWORD '${DB_PASS}';
  ELSE
    ALTER USER \"${DB_USER}\" WITH PASSWORD '${DB_PASS}';
  END IF;
END\$\$;" 2>/dev/null || true
  sudo -u postgres psql -c \
    "CREATE DATABASE \"${DB_NAME}\" OWNER \"${DB_USER}\" ENCODING 'UTF8';" 2>/dev/null \
    || warn "Database '${DB_NAME}' may already exist — continuing."
  success "PostgreSQL database ready."

  # -- Python virtualenv + dependencies ------------------------------------
  VENV_DIR="${SCRIPT_DIR}/venv"
  info "Creating Python virtual environment at ${VENV_DIR}..."
  python3 -m venv "$VENV_DIR"
  # shellcheck source=/dev/null
  source "${VENV_DIR}/bin/activate"

  info "Installing Python dependencies (this may take a few minutes)..."
  pip install --quiet --upgrade pip
  pip install --quiet -r "${SCRIPT_DIR}/requirements.txt"
  success "Python dependencies installed."

  # -- Build frontend -------------------------------------------------------
  info "Installing Node.js dependencies..."
  cd "${SCRIPT_DIR}/frontend"
  npm install --silent
  info "Building frontend..."
  npm run build
  success "Frontend built → frontend/dist/"
  cd "$SCRIPT_DIR"

  # -- Collect static files (needs env loaded) -----------------------------
  info "Collecting Django static files..."
  set -a; . "$ENV_FILE"; set +a
  cd "${SCRIPT_DIR}/securityhub"
  python manage.py collectstatic --noinput --quiet
  cd "$SCRIPT_DIR"
  success "Static files collected."

  # -- Write systemd service -----------------------------------------------
  APP_USER="${SUDO_USER:-$USER}"
  VENV_BIN="${VENV_DIR}/bin"
  SERVICE_FILE="/etc/systemd/system/securityhub.service"

  if command -v systemctl &>/dev/null; then
    info "Writing systemd service to ${SERVICE_FILE}..."
    sudo tee "$SERVICE_FILE" >/dev/null <<SYSTEMD
[Unit]
Description=SecurityHub Community Edition (gunicorn)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${SCRIPT_DIR}/securityhub
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_BIN}/gunicorn \\
    --workers 3 \\
    --bind 127.0.0.1:8000 \\
    --timeout 120 \\
    --access-logfile - \\
    securityhub.wsgi:application
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD
    sudo systemctl daemon-reload
    sudo systemctl enable --now securityhub
    success "systemd service 'securityhub' enabled and started."
  else
    warn "systemd not found — skipping service setup."
    warn "Start the app manually:"
    warn "  source venv/bin/activate && cd securityhub"
    warn "  gunicorn --workers 3 --bind 127.0.0.1:8000 securityhub.wsgi:application"
  fi

  # -- Write Nginx config --------------------------------------------------
  NGINX_CONF="/etc/nginx/sites-available/securityhub"
  NGINX_ENABLED="/etc/nginx/sites-enabled/securityhub"
  NGINX_CONF_D="/etc/nginx/conf.d/securityhub.conf"

  FRONTEND_DIST="${SCRIPT_DIR}/frontend/dist"
  STATIC_DIR="${SCRIPT_DIR}/securityhub/static"
  MEDIA_DIR="${SCRIPT_DIR}/securityhub/media"

  NGINX_BLOCK="server {
    listen 80;
    server_name ${DOMAIN};
    server_tokens off;
    client_max_body_size 25M;

    add_header X-Frame-Options       \"SAMEORIGIN\"                       always;
    add_header X-Content-Type-Options \"nosniff\"                          always;
    add_header X-XSS-Protection       \"1; mode=block\"                   always;
    add_header Referrer-Policy        \"strict-origin-when-cross-origin\" always;

    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host              \$host;
        proxy_redirect off;
        proxy_read_timeout 120s;
    }

    location /static/ {
        alias ${STATIC_DIR}/;
        expires 30d;
        add_header Cache-Control \"public, immutable\";
    }

    location /media/profile/ { alias ${MEDIA_DIR}/profile/; expires 7d; }
    location /media/company/  { alias ${MEDIA_DIR}/company/;  expires 7d; }
    location /media/report/   { alias ${MEDIA_DIR}/report/;   expires 1d; }

    location / {
        root  ${FRONTEND_DIST};
        index index.html;
        try_files \$uri \$uri/ /index.html =404;
        location ~* \.(js|css|woff2?|ttf|svg|png|jpg|ico)\$ {
            expires 1y;
            add_header Cache-Control \"public, immutable\";
        }
    }

    access_log /var/log/nginx/securityhub_access.log;
    error_log  /var/log/nginx/securityhub_error.log;
}"

  info "Writing Nginx configuration..."
  if [[ -d /etc/nginx/sites-available ]]; then
    # Debian/Ubuntu layout
    echo "$NGINX_BLOCK" | sudo tee "$NGINX_CONF" >/dev/null
    sudo ln -sf "$NGINX_CONF" "$NGINX_ENABLED"
    sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
  else
    # RHEL/Fedora/Arch/etc. layout
    echo "$NGINX_BLOCK" | sudo tee "$NGINX_CONF_D" >/dev/null
  fi

  sudo nginx -t && sudo systemctl enable --now nginx && sudo nginx -s reload 2>/dev/null || \
  sudo service nginx reload 2>/dev/null || \
  warn "Could not reload Nginx — check 'sudo nginx -t' and start it manually."
  success "Nginx configured."
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Database migrations + first-time setup
# ══════════════════════════════════════════════════════════════════════════════
printf "\n${BOLD}[6/6] Database setup & first-time configuration${NC}\n"
hr

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  BACKEND_CONTAINER="$($COMPOSE_CMD ps -q securityhub 2>/dev/null | head -1)"
  [[ -z "$BACKEND_CONTAINER" ]] && die "Cannot find 'securityhub' container. Check: ${COMPOSE_CMD} ps"

  info "Running migrations..."
  $DOCKER_CMD exec "$BACKEND_CONTAINER" python securityhub/manage.py migrate --run-syncdb

  info "Running first-time setup..."
  $DOCKER_CMD exec \
    -e SETUP_USERNAME="$ADMIN_USER" -e SETUP_EMAIL="$ADMIN_EMAIL" \
    -e SETUP_FULL_NAME="$ADMIN_FULL_NAME" -e SETUP_PASSWORD="$ADMIN_PASS" \
    "$BACKEND_CONTAINER" \
    python securityhub/manage.py first_setup --skip-gtk-check \
    || warn "first_setup returned non-zero (admin may already exist — this is safe)."

  info "Collecting static files..."
  $DOCKER_CMD exec "$BACKEND_CONTAINER" python securityhub/manage.py collectstatic --noinput --quiet

else
  # Activate venv; .env already sourced above
  source "${SCRIPT_DIR}/venv/bin/activate"
  set -a; . "$ENV_FILE"; set +a
  cd "${SCRIPT_DIR}/securityhub"

  info "Running migrations..."
  python manage.py migrate --run-syncdb

  info "Running first-time setup..."
  python manage.py first_setup --skip-gtk-check \
    || warn "first_setup returned non-zero (admin may already exist — this is safe)."

  cd "$SCRIPT_DIR"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Post-startup verification
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$DEPLOY_MODE" == "docker" ]]; then
  info "Verifying app is reachable..."
  _check_url="https://localhost:8443/api/config/ping/"
  _http_code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$_check_url" 2>/dev/null || true)"
  if [[ "$_http_code" == "200" ]]; then
    success "API responding at ${_check_url}"
  else
    warn "API health check returned HTTP ${_http_code:-no response} — the app may still be initializing."
    warn "Test manually: curl -sk https://localhost:8443/api/config/ping/"
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════════════════
printf "\n"
hr
printf "\n  ${BOLD}${GREEN}✔  SecurityHub is ready!${NC}\n\n"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  # Nginx maps :80→host:3000 (redirects to HTTPS) and :443→host:8443.
  # Always show the port-qualified HTTPS URL since that's what the browser needs.
  if [[ "$IS_WSL" == "true" ]]; then
    printf "  ${BOLD}Open in your Windows browser:${NC}\n"
    printf "    ${CYAN}https://localhost:8443${NC}\n"
    printf "    ${DIM}(port 3000 redirects here — accept the self-signed cert warning)${NC}\n"
  elif [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
    printf "  ${BOLD}URL:${NC}  ${CYAN}https://localhost:8443${NC}\n"
    printf "        ${DIM}(port 3000 redirects to HTTPS — accept the self-signed cert warning)${NC}\n"
  else
    printf "  ${BOLD}URL:${NC}  ${CYAN}${BASE_URL}${NC}\n"
    printf "        ${DIM}(make sure your DNS / reverse proxy points to this server's port 8443)${NC}\n"
  fi
else
  printf "  ${BOLD}URL:${NC}  ${CYAN}${BASE_URL}${NC}\n"
fi

printf "\n"
printf "  ${BOLD}Username:${NC}  ${ADMIN_USER}\n"
printf "  ${BOLD}Password:${NC}  ${YELLOW}${ADMIN_PASS}${NC}\n"
printf "\n"
printf "  ${YELLOW}${BOLD}⚠  Change the admin password after your first login.${NC}\n"
printf "\n"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  printf "  ${BOLD}Useful commands:${NC}\n"
  printf "    ${DIM}Logs:${NC}          ${COMPOSE_CMD} logs -f\n"
  printf "    ${DIM}Stop:${NC}          ${COMPOSE_CMD} down\n"
  printf "    ${DIM}Restart:${NC}       ${COMPOSE_CMD} restart\n"
  printf "    ${DIM}Reconfigure:${NC}   bash install.sh\n"
else
  printf "  ${BOLD}Useful commands:${NC}\n"
  printf "    ${DIM}App logs:${NC}      journalctl -u securityhub -f\n"
  printf "    ${DIM}Nginx logs:${NC}    tail -f /var/log/nginx/securityhub_error.log\n"
  printf "    ${DIM}Stop:${NC}          sudo systemctl stop securityhub nginx\n"
  printf "    ${DIM}Restart:${NC}       sudo systemctl restart securityhub\n"
  printf "    ${DIM}Reconfigure:${NC}   bash install.sh\n"
fi
printf "\n"
hr
printf "\n"
