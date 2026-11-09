#!/usr/bin/env bash
# ServerPulse installer
# Created by ArshamSmok · https://github.com/arshamsmok/serverpulse
set -euo pipefail

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/arshamsmok/serverpulse/main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/serverpulse}"
CONF_DIR="${CONF_DIR:-/etc/serverpulse}"
DATA_DIR="${DATA_DIR:-/var/lib/serverpulse}"
CONF_FILE="$CONF_DIR/config.json"
PORT="${PORT:-8585}"

info() { echo "==> $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

# Use app.py next to this script if it exists; otherwise download it from GitHub
fetch_app() {
  local src_dir="$1" dest="$2"
  if [ -f "$src_dir/app.py" ]; then
    cp "$src_dir/app.py" "$dest"
  else
    info "Downloading app.py from GitHub..."
    curl -fsSL "$REPO_RAW/app.py" -o "$dest" \
      || fail "Could not download app.py from GitHub. Check the internet connection."
  fi
}

# Make sure the server can reach PyPI before installing anything
check_internet() {
  info "Checking internet connection..."
  if ! curl -fsS --max-time 10 -o /dev/null https://pypi.org/simple/flask/; then
    fail "Cannot reach pypi.org. Check the server's internet connection and DNS, then run the installer again."
  fi
}

# Write config.json: hashed password, session key, history, services and alerts
# write_config USER PASS PORT CONF_PATH TG_TOKEN TG_CHAT
write_config() {
  local user="$1" pass="$2" port="$3" conf="$4" tg_token="$5" tg_chat="$6"
  SP_USER="$user" SP_PASS="$pass" SP_PORT="$port" SP_CONF="$conf" \
  SP_TG_TOKEN="$tg_token" SP_TG_CHAT="$tg_chat" DATA_DIR="$DATA_DIR" \
    "$INSTALL_DIR/venv/bin/python" - <<'PY'
import json
import os
import secrets

from werkzeug.security import generate_password_hash

conf = {
    "username": os.environ["SP_USER"],
    "password_hash": generate_password_hash(os.environ["SP_PASS"]),
    "secret_key": secrets.token_hex(32),
    "host": "0.0.0.0",
    "port": int(os.environ["SP_PORT"]),
    "db_path": os.path.join(os.environ["DATA_DIR"], "history.db"),
    "sample_interval": 60,
    "services": ["serverpulse"],
    "alerts": {
        "telegram_token": os.environ.get("SP_TG_TOKEN", ""),
        "chat_id": os.environ.get("SP_TG_CHAT", ""),
        "cpu": 90,
        "ram": 90,
        "disk": 90,
        "cooldown": 900,
    },
}
path = os.environ["SP_CONF"]
with open(path, "w", encoding="utf-8") as f:
    json.dump(conf, f, ensure_ascii=False, indent=2)
os.chmod(path, 0o600)
PY
}

write_service() {
  cat > /etc/systemd/system/serverpulse.service <<EOF
[Unit]
Description=ServerPulse Monitor
After=network.target

[Service]
WorkingDirectory=$INSTALL_DIR
Environment=SERVERPULSE_CONFIG=$CONF_FILE
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
}

public_ip() {
  local ip
  ip="$(curl -s --max-time 5 https://api.ipify.org || true)"
  if [ -z "$ip" ]; then
    ip="$(hostname -I | awk '{print $1}')"
  fi
  echo "$ip"
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "Please run with sudo: sudo bash install.sh"
  fi

  local src_dir
  src_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

  local username password generated=0 tg_token tg_chat
  read -r -p "Admin username [admin]: " username
  username="${username:-admin}"
  read -r -s -p "Password (leave empty for a random one): " password
  echo
  if [ -z "$password" ]; then
    password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
    generated=1
  fi

  echo "Telegram alerts (optional, press Enter to skip):"
  read -r -s -p "  Bot token: " tg_token
  echo
  read -r -p "  Chat ID: " tg_chat

  check_internet

  info "Installing system packages..."
  apt-get update -y || fail "apt-get update failed. Check the internet connection."
  apt-get install -y python3-venv python3-pip iputils-ping curl

  info "Preparing files..."
  mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$DATA_DIR"
  fetch_app "$src_dir" "$INSTALL_DIR/app.py"

  info "Installing Python packages (flask, psutil)..."
  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install --quiet --retries 3 --timeout 30 flask psutil \
    || fail "Could not install Python packages. Check the internet connection and run the installer again."

  info "Writing configuration..."
  write_config "$username" "$password" "$PORT" "$CONF_FILE" "$tg_token" "$tg_chat"

  info "Starting the ServerPulse service..."
  write_service
  systemctl daemon-reload
  systemctl enable serverpulse >/dev/null
  systemctl restart serverpulse
  sleep 3
  if ! systemctl is-active --quiet serverpulse; then
    fail "The service did not start. Run: sudo journalctl -u serverpulse -n 50"
  fi

  local ip
  ip="$(public_ip)"
  echo
  echo "============================================"
  echo " ServerPulse is installed and running"
  echo " Login URL : http://$ip:$PORT/"
  echo " Username  : $username"
  if [ "$generated" -eq 1 ]; then
    echo " Password  : $password"
    echo " (This password is shown only once)"
  else
    echo " Password  : the one you entered"
  fi
  if [ -n "$tg_token" ] && [ -n "$tg_chat" ]; then
    echo " Telegram alerts: enabled"
  else
    echo " Telegram alerts: disabled (set them later in $CONF_FILE)"
  fi
  echo "============================================"
  echo "Note: the connection is HTTP. For better security, put it behind Nginx with HTTPS."
  echo "If a firewall is active, allow the port: sudo ufw allow $PORT/tcp"
}

# Run main only when this file is executed directly (not when sourced for tests)
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi
