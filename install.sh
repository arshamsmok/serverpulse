#!/usr/bin/env bash
# ServerPulse - نصب خودکار
# ساخته‌شده توسط ArshamSmok · https://github.com/arshamsmok/serverpulse
set -euo pipefail

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/arshamsmok/serverpulse/main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/serverpulse}"
CONF_DIR="${CONF_DIR:-/etc/serverpulse}"
DATA_DIR="${DATA_DIR:-/var/lib/serverpulse}"
CONF_FILE="$CONF_DIR/config.json"
PORT="${PORT:-8585}"

# app.py را از کنار این اسکریپت برمی‌دارد؛ اگر نبود (مثلاً اجرای یک‌خطی) از گیت‌هاب دانلود می‌کند
fetch_app() {
  local src_dir="$1" dest="$2"
  if [ -f "$src_dir/app.py" ]; then
    cp "$src_dir/app.py" "$dest"
  else
    echo ">> دانلود app.py از گیت‌هاب..."
    curl -fsSL "$REPO_RAW/app.py" -o "$dest"
  fi
}

# ساخت config.json: رمز هش‌شده، کلید نشست تصادفی، تاریخچه، سرویس‌ها و هشدار
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
    echo "این اسکریپت باید با sudo اجرا شود."
    exit 1
  fi

  local src_dir
  src_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

  local username password generated=0 tg_token tg_chat
  read -r -p "نام کاربری ورود [admin]: " username
  username="${username:-admin}"
  read -r -s -p "رمز عبور (خالی = رمز تصادفی): " password
  echo
  if [ -z "$password" ]; then
    password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
    generated=1
  fi

  echo "هشدار تلگرام (اختیاری؛ برای رد کردن Enter بزنید):"
  read -r -s -p "  توکن ربات: " tg_token
  echo
  read -r -p "  Chat ID: " tg_chat

  echo ">> نصب پیش‌نیازها..."
  apt-get update -y
  apt-get install -y python3-venv python3-pip iputils-ping curl

  echo ">> آماده‌سازی فایل‌ها..."
  mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$DATA_DIR"
  fetch_app "$src_dir" "$INSTALL_DIR/app.py"

  echo ">> نصب وابستگی‌های پایتون..."
  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install --quiet flask psutil

  echo ">> ساخت تنظیمات..."
  write_config "$username" "$password" "$PORT" "$CONF_FILE" "$tg_token" "$tg_chat"

  echo ">> راه‌اندازی سرویس..."
  write_service
  systemctl daemon-reload
  systemctl enable serverpulse >/dev/null
  systemctl restart serverpulse

  local ip
  ip="$(public_ip)"
  echo
  echo "============================================"
  echo " ServerPulse نصب شد"
  echo " لینک ورود : http://$ip:$PORT/"
  echo " نام کاربری: $username"
  if [ "$generated" -eq 1 ]; then
    echo " رمز عبور : $password"
    echo " (این رمز فقط همین یک بار نمایش داده می‌شود)"
  else
    echo " رمز عبور : همان رمزی که وارد کردید"
  fi
  if [ -n "$tg_token" ] && [ -n "$tg_chat" ]; then
    echo " هشدار تلگرام: فعال"
  else
    echo " هشدار تلگرام: غیرفعال (بعداً در $CONF_FILE تنظیم کنید)"
  fi
  echo "============================================"
  echo "نکته: اتصال HTTP است. برای امنیت بیشتر پشت Nginx با HTTPS قرار دهید."
  echo "اگر فایروال فعال است: sudo ufw allow $PORT/tcp"
}

# فقط وقتی مستقیم اجرا شود main را صدا بزن (برای تست با source هم امکان‌پذیر است)
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi
