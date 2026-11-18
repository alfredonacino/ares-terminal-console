#!/usr/bin/env bash
#
# Standard deployment for Claude Code generated apps.
#
#   ./deploy.sh              deploy this repo to the app server
#   ./deploy.sh --dry-run    show what rsync would transfer, change nothing
#   ./deploy.sh --logs       tail the remote pm2 logs after deploying
#
# The whole thing is idempotent: run it as often as you like. Everything the
# running app owns on the server (.env, data/, storage/, logs/) is preserved.
#
# Nothing about a server is baked into this script. The target is resolved in
# this order, first hit wins:
#   1. the environment            DEPLOY_HOST=other-box ./deploy.sh
#   2. ./.env.deploy              per-project override, git-ignored
#   3. ~/.claude/deploy/target.env   the default for this machine
#
# Override any of these with environment variables:
#   DEPLOY_HOST DEPLOY_USER DEPLOY_BASE APP_NAME APP_PORT NODE_VERSION
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fill in KEY=VALUE lines from a file, without disturbing anything already set
# in the environment. That is what makes the precedence above work.
load_defaults() {
  local file="$1" line key value
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) continue ;; esac
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
    if [ -z "${!key:-}" ]; then export "$key=$value"; fi
  done < "$file"
}

load_defaults "${REPO_DIR}/.env.deploy"
load_defaults "${DEPLOY_STANDARD_DIR:-$HOME/.claude/deploy}/target.env"

# --------------------------------------------------------------- settings --
if [ -z "${DEPLOY_HOST:-}" ]; then
  cat >&2 <<'NOHOST'
DEPLOY_HOST is not set, so there is no server to deploy to.

For one run:
    DEPLOY_HOST=my-server ./deploy.sh

For this project only, in a git-ignored .env.deploy next to this script:
    DEPLOY_HOST=my-server
    DEPLOY_USER=someone

For every app on this machine, in ~/.claude/deploy/target.env.
NOHOST
  exit 2
fi

DEPLOY_USER="${DEPLOY_USER:-$(id -un)}"
DEPLOY_BASE="${DEPLOY_BASE:-/home/${DEPLOY_USER}}"
NODE_VERSION="${NODE_VERSION:-24.20.0}"
APP_PORT="${APP_PORT:-3222}"
HEALTH_PATH="${HEALTH_PATH:-/healthz}"

# Health check target. HEALTH_SCHEME=https makes the check skip certificate
# verification: it runs on the server against 127.0.0.1 to prove the process is
# up, not to validate the PKI (and a self-signed cert would fail validation).
HEALTH_SCHEME="${HEALTH_SCHEME:-http}"
HEALTH_PORT="${HEALTH_PORT:-$APP_PORT}"

# Command run on the server after dependencies install, before pm2 starts.
# Used for one-off preparation such as generating a TLS certificate.
POST_INSTALL_CMD="${POST_INSTALL_CMD:-}"

# Dependency install on the server. Empty = npm ci / npm install (Node apps).
# Python/Go apps set it, e.g. "python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt".
INSTALL_CMD="${INSTALL_CMD:-python3 -m venv .venv && .venv/bin/pip install -q --upgrade pip && .venv/bin/pip install -q -r requirements.txt}"

# Secrets generated once on the server, then never touched again.
# Format: NAME:BYTES:ENCODING
GENERATE_SECRETS="${GENERATE_SECRETS:-APP_KEY:32:hex}"

cd "$REPO_DIR"

APP_NAME="${APP_NAME:-ares-terminal-console}"     # the app key: pm2 process and server directory
REMOTE="${DEPLOY_USER}@${DEPLOY_HOST}"
TARGET="${DEPLOY_BASE}/${APP_NAME}"
NODE_HOME="${DEPLOY_BASE}/.local/node-v${NODE_VERSION}"
NODE_CURRENT="${DEPLOY_BASE}/.local/node-current"

DRY_RUN=0
FOLLOW_LOGS=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --logs) FOLLOW_LOGS=1 ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }
ssh_do() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" "$@"; }

say "Deploying ${APP_NAME} to ${REMOTE}:${TARGET}"

# ------------------------------------------------------------- preflight ---
say "Checking connectivity"
ssh_do "echo connected as \$(whoami) on \$(hostname)"

if ! ssh_do "command -v pm2 >/dev/null"; then
  echo "pm2 is not installed on ${DEPLOY_HOST}. Install it with: npm i -g pm2" >&2
  exit 1
fi

# --------------------------------------------------- pinned Node runtime ---
# The system Node on the server may be older than the app needs, and other
# apps depend on it, so a private runtime is installed under ~/.local.
say "Ensuring Node v${NODE_VERSION} runtime on the server"
ssh_do "bash -s" <<REMOTE_NODE
set -euo pipefail
if [ ! -x "${NODE_HOME}/bin/node" ]; then
  echo "installing node v${NODE_VERSION} into ${NODE_HOME}"
  mkdir -p "${DEPLOY_BASE}/.local"
  tmp=\$(mktemp -d)
  trap 'rm -rf "\$tmp"' EXIT
  curl -fsSL --max-time 300 -o "\$tmp/node.tar.xz" \
    "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
  tar -xJf "\$tmp/node.tar.xz" -C "\$tmp"
  rm -rf "${NODE_HOME}"
  mv "\$tmp/node-v${NODE_VERSION}-linux-x64" "${NODE_HOME}"
fi
ln -sfn "${NODE_HOME}" "${NODE_CURRENT}"
"${NODE_CURRENT}/bin/node" -v
REMOTE_NODE

# ------------------------------------------------------------ file sync ----
say "Syncing files"
RSYNC_FLAGS=(-az --delete --human-readable --info=stats1)
[ "$DRY_RUN" -eq 1 ] && RSYNC_FLAGS+=(--dry-run --itemize-changes)

# --delete keeps the remote tree clean, so anything the app owns at runtime
# must be protected explicitly.
rsync "${RSYNC_FLAGS[@]}" \
  --exclude '.git/' \
  --exclude 'node_modules/' \
  --exclude '.venv/' \
  --exclude 'venv/' \
  --exclude 'build/' \
  --exclude 'dist/' \
  --exclude 'release/' \
  --exclude '.suite/' \
  --exclude '__pycache__/' \
  --exclude 'packaging/docs/node_modules/' \
  --exclude '.env' \
  --exclude '.env.deploy' \
  --exclude 'data/' \
  --exclude 'storage/' \
  --exclude 'logs/' \
  --exclude 'certs/' \
  --exclude '*.log' \
  --exclude '.DS_Store' \
  --rsync-path="mkdir -p '${TARGET}' && rsync" \
  ./ "${REMOTE}:${TARGET}/"

if [ "$DRY_RUN" -eq 1 ]; then
  say "Dry run finished - nothing was changed on the server"
  exit 0
fi

# ------------------------------------------- dependencies, env, pm2 boot ---
say "Installing dependencies and (re)starting under pm2"
ssh_do "bash -s" <<REMOTE_DEPLOY
set -euo pipefail
export PATH="${NODE_CURRENT}/bin:\$PATH"
export PM2_NODE_INTERPRETER="${NODE_CURRENT}/bin/node"
cd "${TARGET}"
mkdir -p logs data storage

if [ -n "${INSTALL_CMD}" ]; then
  echo "installing dependencies: ${INSTALL_CMD}"
  ${INSTALL_CMD}
elif [ -f package-lock.json ]; then
  npm ci --omit=dev --no-audit --no-fund
else
  npm install --omit=dev --no-audit --no-fund
fi

# The .env is created once and then left alone: it holds the keys that
# encrypt MFA secrets and sign the audit chain. Losing it invalidates both.
if [ ! -f .env ]; then
  echo "creating .env with freshly generated secrets"
  {
    echo "# Generated by deploy.sh on \$(date -Iseconds). Keep this file - do not rotate casually."
    echo "NODE_ENV=production"
    echo "PORT=${APP_PORT}"
    echo "HOST=0.0.0.0"
    for spec in ${GENERATE_SECRETS}; do
      name="\${spec%%:*}"; rest="\${spec#*:}"; bytes="\${rest%%:*}"; enc="\${rest##*:}"
      echo "\${name}=\$(node -e "console.log(require('crypto').randomBytes(\${bytes}).toString('\${enc}'))")"
    done
    if [ -f deploy/env.production ]; then cat deploy/env.production; fi
  } > .env
  chmod 600 .env
else
  echo ".env already present - left untouched"
  # New releases may introduce new settings. Keys that are missing get
  # appended; keys that are already there are never modified, so anything
  # tuned on the server survives.
  if [ -f deploy/env.production ]; then
    added=""
    while IFS= read -r line; do
      case "\$line" in ''|'#'*) continue ;; esac
      key="\${line%%=*}"
      if ! grep -q "^\${key}=" .env; then
        printf '%s\n' "\$line" >> .env
        added="\$added \$key"
      fi
    done < deploy/env.production
    [ -n "\$added" ] && echo "added new settings to .env:\$added" || echo ".env is up to date"
  fi
fi

if [ -n "${POST_INSTALL_CMD}" ]; then
  echo "running post-install: ${POST_INSTALL_CMD}"
  ${POST_INSTALL_CMD}
fi

pm2 startOrReload ecosystem.config.cjs --update-env
pm2 save

# Make sure the whole pm2 process list comes back after a reboot.
if ! systemctl is-enabled "pm2-\$(whoami).service" >/dev/null 2>&1; then
  echo
  echo "!! pm2 is not yet enabled at boot. Run this once, with sudo:"
  pm2 startup systemd -u "\$(whoami)" --hp "\$HOME" | tail -3 || true   # prints the sudo command and exits non-zero
else
  echo "boot persistence: pm2-\$(whoami).service is enabled"
fi
REMOTE_DEPLOY

# ------------------------------------------------------------- verify ------
say "Health check"
sleep 4
CURL_FLAGS="-sf"
[ "$HEALTH_SCHEME" = "https" ] && CURL_FLAGS="-sfk"

if ssh_do "curl ${CURL_FLAGS} --max-time 10 ${HEALTH_SCHEME}://127.0.0.1:${HEALTH_PORT}${HEALTH_PATH}"; then
  printf '\n\033[1;32m==> %s is live at %s://%s:%s\033[0m\n' "$APP_NAME" "$HEALTH_SCHEME" "$DEPLOY_HOST" "$HEALTH_PORT"
else
  printf '\n\033[1;31m==> Health check failed. Recent logs:\033[0m\n'
  ssh_do "pm2 logs '${APP_NAME}' --lines 40 --nostream" || true
  exit 1
fi

ssh_do "pm2 describe '${APP_NAME}' | grep -E 'status|watch|restarts|uptime|exec mode|interpreter' || true"

if [ "$FOLLOW_LOGS" -eq 1 ]; then
  say "Tailing logs (Ctrl-C to stop)"
  ssh -t "$REMOTE" "pm2 logs '${APP_NAME}'"
fi
