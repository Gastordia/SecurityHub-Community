#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SecurityHub Community Edition — Uninstaller
# ══════════════════════════════════════════════════════════════════════════════
# Removes only what install.sh created.
# Source code, Docker, Node.js, and system packages are never touched.
#
# Usage:
#   bash uninstall.sh                   # interactive (asks before each step)
#   bash uninstall.sh --keep-data       # skip database / Docker volume removal
#   bash uninstall.sh --keep-env        # leave the .env file in place
#   bash uninstall.sh --yes             # non-interactive (still shows what runs)
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
skip()    { printf "  ${DIM}↷ skipped — %s${NC}\n" "$*"; }

# ── Flags ─────────────────────────────────────────────────────────────────────
KEEP_DATA=false
KEEP_ENV=false
NON_INTERACTIVE=false

for arg in "$@"; do
  case "$arg" in
    --keep-data) KEEP_DATA=true ;;
    --keep-env)  KEEP_ENV=true  ;;
    --yes|-y)    NON_INTERACTIVE=true ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# ── Banner ────────────────────────────────────────────────────────────────────
[[ -t 1 ]] && clear
printf "\n${BOLD}${RED}"
cat <<'BANNER'
  ╔═══════════════════════════════════════════════════════╗
  ║      SecurityHub Community Edition — Uninstaller      ║
  ╚═══════════════════════════════════════════════════════╝
BANNER
printf "${NC}\n"
hr
printf "\n"
printf "  This script removes ${BOLD}only what install.sh created${NC}.\n"
printf "  It will ${BOLD}NOT${NC} remove: Docker, Node.js, system packages, or your source code.\n"
printf "\n"

# ── Read .env to determine mode and DB credentials ────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
  warn ".env not found at ${ENV_FILE}."
  warn "Cannot determine deployment mode or database credentials automatically."
  printf "\n  ${BOLD}If you used Docker:${NC}\n"
  printf "    cd ${SCRIPT_DIR} && docker compose down -v\n"
  printf "\n  ${BOLD}If you used bare-metal:${NC}\n"
  printf "    sudo systemctl disable --now securityhub\n"
  printf "    sudo rm -f /etc/systemd/system/securityhub.service\n"
  printf "    sudo rm -f /etc/nginx/sites-enabled/securityhub\n"
  printf "    sudo rm -f /etc/nginx/sites-available/securityhub\n"
  printf "    sudo rm -f /etc/nginx/conf.d/securityhub.conf\n"
  printf "    rm -rf ${SCRIPT_DIR}/venv ${SCRIPT_DIR}/frontend/dist\n"
  printf "\n"
  exit 0
fi

# Load .env
set -a
# shellcheck source=/dev/null
. "$ENV_FILE" 2>/dev/null || true
set +a

USE_DOCKER="${USE_DOCKER:-True}"
DEPLOY_MODE="docker"
[[ "${USE_DOCKER}" == "False" ]] && DEPLOY_MODE="baremetal"

DB_NAME="${POSTGRES_DB:-securityhub}"
DB_USER="${POSTGRES_USER:-securityhub_user}"

# ── Summary of what will be removed ──────────────────────────────────────────
printf "  ${BOLD}Deployment mode detected:${NC} ${DEPLOY_MODE}\n\n"

if [[ "$DEPLOY_MODE" == "docker" ]]; then
  printf "  ${BOLD}Will remove:${NC}\n"
  printf "    • Docker containers (securityhub, postgres, nginx)\n"
  printf "    • Docker network created by Compose\n"
  if [[ "$KEEP_DATA" == "false" ]]; then
    printf "    • ${RED}Docker volumes (database data)${NC}\n"
  else
    printf "    • ${DIM}Docker volumes — SKIPPED (--keep-data)${NC}\n"
  fi
  printf "    • Docker images built by this project\n"
  if [[ "$KEEP_ENV" == "false" ]]; then
    printf "    • ${SCRIPT_DIR}/.env\n"
  else
    printf "    • ${DIM}.env — SKIPPED (--keep-env)${NC}\n"
  fi
else
  printf "  ${BOLD}Will remove:${NC}\n"
  printf "    • systemd service: securityhub\n"
  printf "    • Nginx config (securityhub site)\n"
  if [[ "$KEEP_DATA" == "false" ]]; then
    printf "    • ${RED}PostgreSQL database '${DB_NAME}' and user '${DB_USER}'${NC}\n"
  else
    printf "    • ${DIM}PostgreSQL database/user — SKIPPED (--keep-data)${NC}\n"
  fi
  printf "    • ${SCRIPT_DIR}/venv\n"
  printf "    • ${SCRIPT_DIR}/frontend/dist\n"
  printf "    • ${SCRIPT_DIR}/securityhub/staticfiles (collected statics)\n"
  if [[ "$KEEP_ENV" == "false" ]]; then
    printf "    • ${SCRIPT_DIR}/.env\n"
  else
    printf "    • ${DIM}.env — SKIPPED (--keep-env)${NC}\n"
  fi
fi

printf "\n  ${BOLD}Will NOT remove:${NC}\n"
printf "    • Docker, Node.js, system packages (python3, postgresql, nginx)\n"
printf "    • Your project source code\n"
printf "    • ${SCRIPT_DIR}/securityhub/media (uploaded files)\n"
printf "\n"
hr
printf "\n"

# ── Final confirmation ────────────────────────────────────────────────────────
if [[ "$NON_INTERACTIVE" == "false" ]]; then
  printf "  ${BOLD}${RED}This action is irreversible.${NC}\n\n"
  printf "  Type ${BOLD}yes${NC} to continue, anything else to abort: "
  read -r _confirm || _confirm=""
  if [[ "$_confirm" != "yes" ]]; then
    printf "\n  Aborted. Nothing was changed.\n\n"
    exit 0
  fi
fi

printf "\n"

# ══════════════════════════════════════════════════════════════════════════════
# Docker mode cleanup
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$DEPLOY_MODE" == "docker" ]]; then

  # Detect compose command
  COMPOSE_CMD=""
  if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  fi

  if [[ -z "$COMPOSE_CMD" ]]; then
    warn "Docker or Docker Compose not found — cannot stop containers automatically."
    warn "If containers are still running, stop them with:  docker compose down -v"
  else
    cd "$SCRIPT_DIR"

    # Stop and remove containers + network (+ volumes if not keeping data)
    if [[ "$KEEP_DATA" == "false" ]]; then
      info "Stopping containers and removing volumes..."
      $COMPOSE_CMD down --volumes --remove-orphans 2>/dev/null || \
        warn "docker compose down failed — containers may already be stopped."
      success "Containers, network, and volumes removed."
    else
      info "Stopping containers (preserving volumes)..."
      $COMPOSE_CMD down --remove-orphans 2>/dev/null || \
        warn "docker compose down failed — containers may already be stopped."
      success "Containers and network removed. Volumes preserved."
    fi

    # Remove images built by this project
    info "Removing project Docker images..."
    PROJECT_NAME="$(basename "$SCRIPT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')"
    # Images are tagged <project>_<service> (Compose v1) or <project>-<service> (Compose v2)
    for pattern in "${PROJECT_NAME}_securityhub" "${PROJECT_NAME}-securityhub" \
                   "${PROJECT_NAME}_nginx"        "${PROJECT_NAME}-nginx"; do
      if docker image inspect "$pattern" &>/dev/null 2>&1; then
        docker rmi "$pattern" 2>/dev/null && success "Removed image: ${pattern}" || \
          warn "Could not remove image ${pattern} (may be in use elsewhere)."
      fi
    done
    # Also remove dangling images left by the build
    docker image prune -f --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
      2>/dev/null || true
  fi

fi

# ══════════════════════════════════════════════════════════════════════════════
# Bare-metal mode cleanup
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$DEPLOY_MODE" == "baremetal" ]]; then

  # ── systemd service ─────────────────────────────────────────────────────────
  SERVICE_FILE="/etc/systemd/system/securityhub.service"
  if [[ -f "$SERVICE_FILE" ]]; then
    info "Stopping and disabling securityhub service..."
    sudo systemctl stop securityhub    2>/dev/null || true
    sudo systemctl disable securityhub 2>/dev/null || true
    sudo rm -f "$SERVICE_FILE"
    sudo systemctl daemon-reload       2>/dev/null || true
    success "systemd service removed."
  else
    skip "systemd service (not found at ${SERVICE_FILE})."
  fi

  # ── Nginx config ─────────────────────────────────────────────────────────────
  NGINX_SITES_AVAIL="/etc/nginx/sites-available/securityhub"
  NGINX_SITES_ENAB="/etc/nginx/sites-enabled/securityhub"
  NGINX_CONF_D="/etc/nginx/conf.d/securityhub.conf"
  NGINX_CHANGED=false

  if [[ -f "$NGINX_SITES_AVAIL" ]]; then
    info "Removing Nginx site config (sites-available/sites-enabled layout)..."
    sudo rm -f "$NGINX_SITES_ENAB"   2>/dev/null || true
    sudo rm -f "$NGINX_SITES_AVAIL"  2>/dev/null || true
    NGINX_CHANGED=true
    success "Nginx site config removed."
  fi

  if [[ -f "$NGINX_CONF_D" ]]; then
    info "Removing Nginx config (conf.d layout)..."
    sudo rm -f "$NGINX_CONF_D" 2>/dev/null || true
    NGINX_CHANGED=true
    success "Nginx conf.d config removed."
  fi

  if [[ "$NGINX_CHANGED" == "false" ]]; then
    skip "Nginx config (no securityhub config found)."
  else
    # Reload Nginx only if it is running
    if sudo nginx -t 2>/dev/null; then
      sudo systemctl reload nginx 2>/dev/null || \
        sudo service nginx reload  2>/dev/null || \
        warn "Could not reload Nginx — do it manually if it is running."
    fi
  fi

  # ── PostgreSQL database and user ─────────────────────────────────────────────
  if [[ "$KEEP_DATA" == "false" ]]; then
    info "Dropping PostgreSQL database '${DB_NAME}' and user '${DB_USER}'..."
    # Drop database first (user cannot be dropped while it owns objects)
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"${DB_NAME}\";" 2>/dev/null && \
      success "Database '${DB_NAME}' dropped." || \
      warn "Could not drop database '${DB_NAME}' — drop it manually if needed."

    sudo -u postgres psql -c "DROP USER IF EXISTS \"${DB_USER}\";" 2>/dev/null && \
      success "User '${DB_USER}' dropped." || \
      warn "Could not drop user '${DB_USER}' — drop it manually if needed."
  else
    skip "PostgreSQL database and user (--keep-data)."
  fi

  # ── Python virtualenv ────────────────────────────────────────────────────────
  VENV_DIR="${SCRIPT_DIR}/venv"
  if [[ -d "$VENV_DIR" ]]; then
    info "Removing Python virtualenv..."
    rm -rf "$VENV_DIR"
    success "Virtualenv removed: ${VENV_DIR}"
  else
    skip "virtualenv (not found at ${VENV_DIR})."
  fi

  # ── Frontend build output ────────────────────────────────────────────────────
  DIST_DIR="${SCRIPT_DIR}/frontend/dist"
  if [[ -d "$DIST_DIR" ]]; then
    info "Removing frontend build output..."
    rm -rf "$DIST_DIR"
    success "Frontend dist removed: ${DIST_DIR}"
  else
    skip "frontend/dist (not found)."
  fi

  # ── Collected Django static files ────────────────────────────────────────────
  STATIC_DIR="${SCRIPT_DIR}/securityhub/staticfiles"
  if [[ -d "$STATIC_DIR" ]]; then
    info "Removing collected static files..."
    rm -rf "$STATIC_DIR"
    success "Static files removed: ${STATIC_DIR}"
  else
    # Also try the plain static/ path (depends on STATIC_ROOT setting)
    STATIC_DIR2="${SCRIPT_DIR}/securityhub/static"
    if [[ -d "$STATIC_DIR2" ]]; then
      info "Removing collected static files..."
      rm -rf "$STATIC_DIR2"
      success "Static files removed: ${STATIC_DIR2}"
    else
      skip "collected static files (not found)."
    fi
  fi

fi

# ══════════════════════════════════════════════════════════════════════════════
# .env removal (both modes)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$KEEP_ENV" == "false" ]]; then
  if [[ -f "$ENV_FILE" ]]; then
    info "Removing .env..."
    rm -f "$ENV_FILE"
    success ".env removed."
  else
    skip ".env (already gone)."
  fi
else
  skip ".env (--keep-env)."
fi

# ══════════════════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════════════════
printf "\n"
hr
printf "\n  ${BOLD}${GREEN}✔  SecurityHub has been uninstalled.${NC}\n"
printf "\n  Your source code at ${BOLD}${SCRIPT_DIR}${NC} is untouched.\n"

if [[ "$DEPLOY_MODE" == "baremetal" ]]; then
  if [[ -d "${SCRIPT_DIR}/securityhub/media" ]]; then
    printf "\n  ${YELLOW}Note:${NC} Uploaded files are still at:\n"
    printf "    ${SCRIPT_DIR}/securityhub/media\n"
    printf "  Delete that directory manually if you no longer need it.\n"
  fi
fi

printf "\n"
hr
printf "\n"
