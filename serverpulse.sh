#!/usr/bin/env bash
# ServerPulse control menu · Created by ArshamSmok · https://github.com/arshamsmok/serverpulse
set -u

INSTALL_DIR="${INSTALL_DIR:-/opt/serverpulse}"
CONF="${CONF:-/etc/serverpulse/config.json}"
export SERVERPULSE_CONFIG="$CONF"
PY="$INSTALL_DIR/venv/bin/python"
MANAGE="$INSTALL_DIR/manage.py"
REPO_RAW="https://raw.githubusercontent.com/arshamsmok/serverpulse/main"

B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'
CY=$'\033[36m'; GR=$'\033[32m'; RD=$'\033[31m'; YE=$'\033[33m'; WH=$'\033[97m'

if [ "$(id -u)" -ne 0 ] && [ -z "${SP_TEST:-}" ]; then
  echo "${RD}Run as root:${R} sudo serverpulse"
  exit 1
fi

trap 'echo; exit 0' INT

ok()   { echo "  ${GR}✔${R} $*"; }
bad()  { echo "  ${RD}✘${R} $*"; }
note() { echo "  ${CY}›${R} $*"; }
hold() { echo; read -r -p "  ${D}Press Enter to return to the menu${R} " _; }

cfg() { "$PY" -c "import json; print(json.load(open('$CONF')).get('$1',''))" 2>/dev/null; }
lst() { "$PY" -c "import json; v=json.load(open('$CONF')).get('$1',[]); print(', '.join(v) if v else 'any')" 2>/dev/null; }
restart_quiet() { systemctl restart serverpulse >/dev/null 2>&1 || true; }

banner() {
  clear 2>/dev/null || true
  echo "${CY}${B}  ╔══════════════════════════════════════╗${R}"
  echo "${CY}${B}  ║        S E R V E R P U L S E        ║${R}"
  echo "${CY}${B}  ║      Server monitoring control       ║${R}"
  echo "${CY}${B}  ╚══════════════════════════════════════╝${R}"
  local st ver ip port user sc
  st="$(systemctl is-active serverpulse 2>/dev/null || true)"; st="${st:-inactive}"
  ver="$(grep -m1 '^VERSION' "$INSTALL_DIR/app.py" 2>/dev/null | cut -d'"' -f2)"
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  port="$(cfg port)"; user="$(cfg username)"
  if [ "$st" = "active" ]; then sc="${GR}● running${R}"; else sc="${RD}● $st${R}"; fi
  echo "  ${D}Version${R}  ${WH}${ver:-?}${R}     ${D}Service${R}  $sc"
  echo "  ${D}Panel${R}    ${WH}http://${ip:-?}:${port:-?}/${R}"
  echo "  ${D}Admin${R}    ${WH}${user:-?}${R}"
  echo "${D}  ────────────────────────────────────────${R}"
}

show_status() {
  banner
  systemctl status serverpulse --no-pager -l 2>/dev/null | head -n 14 || true
  hold
}

show_logs() {
  banner
  note "Last 60 log lines (run: journalctl -u serverpulse -f to follow)"
  echo
  journalctl -u serverpulse -n 60 --no-pager 2>/dev/null || bad "No logs found"
  hold
}

change_password() {
  banner
  local p1 p2 out
  read -r -s -p "  New password (min 8 characters): " p1; echo
  read -r -s -p "  Repeat password:                 " p2; echo
  if [ "$p1" != "$p2" ]; then bad "Passwords do not match"; hold; return; fi
  if ! out="$(SP_PASS="$p1" "$PY" "$MANAGE" set-password 2>&1)"; then bad "$out"; hold; return; fi
  restart_quiet
  ok "Password changed and service restarted"
  hold
}

change_user() {
  banner
  local u out
  read -r -p "  New admin username: " u
  if ! out="$(SP_VAL="$u" "$PY" "$MANAGE" set-user 2>&1)"; then bad "$out"; hold; return; fi
  restart_quiet
  ok "Username changed to $u and service restarted"
  hold
}

set_list() {
  # set_list FIELD KIND LABEL
  local v out
  note "Current: ${WH}$(lst "$1")${R}"
  note "Comma separated. Empty clears the list (allows everyone)."
  read -r -p "  $3: " v
  if ! out="$(SP_VAL="$v" "$PY" "$MANAGE" set-access "$1" 2>&1)"; then bad "$out"; hold; return; fi
  restart_quiet
  ok "$3 updated and service restarted"
  hold
}

access_menu() {
  while true; do
    banner
    echo "  ${B}Access control${R} ${D}(protects the panel only)${R}"
    echo
    note "Allowed IPs       ${WH}$(lst allow_ips)${R}"
    note "Blocked IPs       ${WH}$(lst deny_ips)${R}"
    note "Allowed domains   ${WH}$(lst allowed_hosts)${R}"
    echo
    echo "  ${D}Make sure your own IP is in the allowed list before you restrict access.${R}"
    echo
    echo "  ${CY}[1]${R} Set allowed IPs / networks    (e.g. 203.0.113.0/24)"
    echo "  ${CY}[2]${R} Set blocked IPs / networks"
    echo "  ${CY}[3]${R} Set allowed domains / hosts   (e.g. monitor.example.com)"
    echo "  ${CY}[0]${R} Back"
    echo
    read -r -p "  ${YE}›${R} Select: " c
    case "$c" in
      1) set_list allow_ips ip "Allowed IPs" ;;
      2) set_list deny_ips ip "Blocked IPs" ;;
      3) set_list allowed_hosts host "Allowed domains" ;;
      0) return ;;
      *) bad "Unknown option"; sleep 1 ;;
    esac
  done
}

telegram() {
  banner
  local t c
  read -r -s -p "  Bot token (empty = disable): " t; echo
  read -r -p "  Chat ID: " c
  SP_TOKEN="$t" SP_CHAT="$c" "$PY" "$MANAGE" set-telegram >/dev/null 2>&1
  restart_quiet
  ok "Telegram settings saved and service restarted"
  hold
}

restart_service() {
  banner
  note "Restarting ServerPulse…"
  restart_quiet
  sleep 2
  if [ "$(systemctl is-active serverpulse 2>/dev/null)" = "active" ]; then ok "Service is running"; else bad "Service did not start. See Live logs."; fi
  hold
}

update_all() {
  banner
  note "Downloading the latest files from GitHub…"
  local tmp f
  tmp="$(mktemp -d)"
  for f in app.py manage.py serverpulse.sh; do
    if ! curl -fsSL "$REPO_RAW/$f" -o "$tmp/$f"; then
      bad "Could not download $f. Check the internet connection."
      rm -rf "$tmp"; hold; return
    fi
  done
  if ! "$PY" -m py_compile "$tmp/app.py" || ! "$PY" -m py_compile "$tmp/manage.py" || ! bash -n "$tmp/serverpulse.sh"; then
    bad "Downloaded files are invalid. Update cancelled."
    rm -rf "$tmp"; hold; return
  fi
  cp "$tmp/app.py" "$INSTALL_DIR/app.py"
  cp "$tmp/manage.py" "$INSTALL_DIR/manage.py"
  cp "$tmp/serverpulse.sh" /usr/local/bin/.serverpulse.new
  chmod 755 /usr/local/bin/.serverpulse.new
  mv -f /usr/local/bin/.serverpulse.new /usr/local/bin/serverpulse
  rm -rf "$tmp"
  restart_quiet
  ok "Updated. Open the menu again to use the new version."
  hold
}

uninstall() {
  banner
  bad "This removes ServerPulse, its settings and its history."
  read -r -p "  Type YES to confirm: " c
  if [ "$c" != "YES" ]; then note "Cancelled"; hold; return; fi
  systemctl disable --now serverpulse >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/serverpulse.service
  rm -rf "$INSTALL_DIR" /etc/serverpulse /var/lib/serverpulse
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f /usr/local/bin/serverpulse
  ok "ServerPulse removed"
  exit 0
}

menu() {
  banner
  echo "  ${CY}[1]${R} Server status          ${CY}[6]${R} Telegram alerts"
  echo "  ${CY}[2]${R} Live logs              ${CY}[7]${R} Restart service"
  echo "  ${CY}[3]${R} Change password        ${CY}[8]${R} Update from GitHub"
  echo "  ${CY}[4]${R} Change username        ${CY}[9]${R} ${RD}Uninstall${R}"
  echo "  ${CY}[5]${R} Access control         ${CY}[0]${R} Exit"
  echo
  read -r -p "  ${YE}›${R} Select: " c
  case "$c" in
    1) show_status ;;
    2) show_logs ;;
    3) change_password ;;
    4) change_user ;;
    5) access_menu ;;
    6) telegram ;;
    7) restart_service ;;
    8) update_all ;;
    9) uninstall ;;
    0) echo; exit 0 ;;
    *) bad "Unknown option"; sleep 1 ;;
  esac
}

while true; do menu; done
