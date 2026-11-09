import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from functools import wraps

import psutil
from flask import Flask, Response, jsonify, redirect, request, session
from werkzeug.security import check_password_hash

app = Flask(__name__)

VERSION = "1.6.0"
HOST = socket.gethostname()
CORES = psutil.cpu_count() or 1

CONFIG_PATH = os.environ.get("SERVERPULSE_CONFIG", "/etc/serverpulse/config.json")
with open(CONFIG_PATH, encoding="utf-8") as _f:
    CFG = json.load(_f)

app.secret_key = CFG["secret_key"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DB_PATH = CFG.get("db_path", "/var/lib/serverpulse/history.db")
SAMPLE_INTERVAL = max(1, int(CFG.get("sample_interval", 60)))
ALERTS = CFG.get("alerts", {})
SERVICES = [s for s in CFG.get("services", []) if re.fullmatch(r"[A-Za-z0-9@._-]+", s)]

BACKGROUND = CFG.get("background_image", "") or ""
if not re.fullmatch(r"https?://[^\s\"'<>(){}\\]+", BACKGROUND):
    BACKGROUND = ""

# ---------- Access control (panel only) ----------

def _nets(items):
    out = []
    for x in items or []:
        try:
            out.append(ipaddress.ip_network(str(x), strict=False))
        except ValueError:
            pass
    return out


ALLOW_NETS = _nets(CFG.get("allow_ips"))
DENY_NETS = _nets(CFG.get("deny_ips"))
ALLOWED_HOSTS = {str(h).lower() for h in (CFG.get("allowed_hosts") or []) if str(h).strip()}


def _in_nets(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


@app.before_request
def access_guard():
    ip = request.remote_addr or ""
    if _in_nets(ip, DENY_NETS):
        return Response("Forbidden", 403, mimetype="text/plain")
    if ALLOW_NETS and not _in_nets(ip, ALLOW_NETS):
        return Response("Forbidden", 403, mimetype="text/plain")
    if ALLOWED_HOSTS and request.host.split(":")[0].lower() not in ALLOWED_HOSTS:
        return Response("Forbidden", 403, mimetype="text/plain")


# ---------- Ping targets ----------
# lat/lng are only used for the map. Anycast IPs (such as 8.8.8.8 and 1.1.1.1) reach the nearest data center.
DEFAULT_TARGETS = [
    {"ip": "8.8.8.8", "name": "Google DNS", "country": "United States", "country_fa": "آمریکا", "code": "US", "lat": 37.42, "lng": -122.08},
    {"ip": "9.9.9.9", "name": "Quad9", "country": "Switzerland", "country_fa": "سوئیس", "code": "CH", "lat": 47.37, "lng": 8.54},
    {"ip": "77.88.8.8", "name": "Yandex DNS", "country": "Russia", "country_fa": "روسیه", "code": "RU", "lat": 55.75, "lng": 37.62},
    {"ip": "223.5.5.5", "name": "AliDNS", "country": "China", "country_fa": "چین", "code": "CN", "lat": 30.29, "lng": 120.16},
    {"ip": "168.126.63.1", "name": "KT DNS", "country": "South Korea", "country_fa": "کره جنوبی", "code": "KR", "lat": 37.57, "lng": 126.98},
    {"ip": "213.133.98.98", "name": "Hetzner DNS", "country": "Germany", "country_fa": "آلمان", "code": "DE", "lat": 49.45, "lng": 11.08},
    {"ip": "193.110.81.0", "name": "dns0.eu", "country": "Netherlands", "country_fa": "هلند", "code": "NL", "lat": 52.37, "lng": 4.90},
    {"ip": "80.67.169.12", "name": "FDN DNS", "country": "France", "country_fa": "فرانسه", "code": "FR", "lat": 48.85, "lng": 2.35},
    {"ip": "1.1.1.1", "name": "Cloudflare", "country": "Global", "country_fa": "جهانی", "code": "ANY", "lat": None, "lng": None},
]


def _normalize(t):
    return {
        "ip": str(t["ip"]),
        "name": str(t.get("name", t["ip"])),
        "country": str(t.get("country", "Unknown")),
        "country_fa": str(t.get("country_fa", t.get("country", ""))),
        "code": str(t.get("code", "ANY"))[:3].upper(),
        "lat": t.get("lat"),
        "lng": t.get("lng"),
    }


# Extra targets can be added in config.json under "targets" (each needs "ip", "name", "country", "code")
TARGETS = [_normalize(t) for t in (CFG.get("targets") or DEFAULT_TARGETS) if t.get("ip")]

PING_INTERVAL = 30
PING_COUNT = 5
RANGES = {"1h": (3600, 60), "24h": (86400, 900), "7d": (7 * 86400, 3600)}
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect("login")
        return fn(*args, **kwargs)
    return wrapper


_lock = threading.Lock()
_snap_lock = threading.Lock()
_ping = {t["ip"]: {"avg": None, "jitter": None, "loss": 100.0} for t in TARGETS}
_server = {"value": None}
_services = {"value": []}
_top = {"value": []}
_snap = {"value": {}}
_net = {"last": psutil.net_io_counters(), "time": time.time()}
_alert_state = {}
_login_state = {"fails": 0, "until": 0.0}
_check_state = {"last": 0.0}
_check_lock = threading.Lock()

RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
LOSS_RE = re.compile(r"([\d.]+)% packet loss")


def ping_host(host, count=PING_COUNT):
    """Multi-packet ping: returns average, jitter (mdev) and packet loss percent."""
    try:
        out = subprocess.run(["ping", "-c", str(count), "-W", "2", host],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return {"avg": None, "jitter": None, "loss": 100.0}
    loss_m = LOSS_RE.search(out)
    loss = float(loss_m.group(1)) if loss_m else 100.0
    rtt = RTT_RE.search(out)
    if not rtt:
        return {"avg": None, "jitter": None, "loss": loss}
    return {"avg": round(float(rtt.group(2)), 1), "jitter": round(float(rtt.group(4)), 1), "loss": loss}


def _probe(ip):
    res = ping_host(ip)
    with _lock:
        _ping[ip] = res


def _ping_loop():
    while True:
        workers = [threading.Thread(target=_probe, args=(t["ip"],), daemon=True) for t in TARGETS]
        for w in workers:
            w.start()
        for w in workers:
            w.join(timeout=25)
        time.sleep(PING_INTERVAL)


def _location_loop():
    url = "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,query,lat,lon"
    while True:
        ok = False
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                d = json.load(r)
            if d.get("status") == "success":
                with _lock:
                    _server["value"] = {
                        "ip": d.get("query"), "country": d.get("country"),
                        "countryCode": d.get("countryCode"), "city": d.get("city"),
                        "isp": d.get("isp"), "lat": d.get("lat"), "lon": d.get("lon"),
                    }
                ok = True
        except Exception:
            pass
        time.sleep(3600 if ok else 300)


def _services_loop():
    while True:
        out = []
        for name in SERVICES:
            try:
                r = subprocess.run(["systemctl", "is-active", name],
                                   capture_output=True, text=True, timeout=5)
                state = r.stdout.strip() or "unknown"
            except Exception:
                state = "unknown"
            out.append({"name": name, "state": state})
        with _lock:
            _services["value"] = out
        time.sleep(30)


def _processes_loop():
    while True:
        rows = []
        for p in psutil.process_iter():
            try:
                cpu = min(p.cpu_percent(None) / CORES, 100.0)
                mem = p.memory_percent()
                rows.append({"pid": p.pid, "name": p.name()[:28],
                             "cpu": round(cpu, 1), "mem": round(mem, 1)})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        rows.sort(key=lambda r: (r["cpu"], r["mem"]), reverse=True)
        with _lock:
            _top["value"] = rows[:8]
        time.sleep(5)


def _collect_loop():
    psutil.cpu_percent(interval=None)
    while True:
        now = time.time()
        net = psutil.net_io_counters()
        dt = max(now - _net["time"], 1e-6)
        rx = (net.bytes_recv - _net["last"].bytes_recv) / dt
        tx = (net.bytes_sent - _net["last"].bytes_sent) / dt
        _net["last"], _net["time"] = net, now

        with _lock:
            pings = {ip: dict(v) for ip, v in _ping.items()}
            server = _server["value"]
            services = list(_services["value"])
            top = list(_top["value"])
        valid = [v["avg"] for v in pings.values() if v["avg"] is not None]

        snap = {
            "ts": int(now),
            "cpu": psutil.cpu_percent(interval=None),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage("/").percent,
            "load": [round(x, 2) for x in os.getloadavg()],
            "uptime": int(now - psutil.boot_time()),
            "rx": rx,
            "tx": tx,
            "ping_avg": round(sum(valid) / len(valid), 1) if valid else None,
            "server": server,
            "services": services,
            "top": top,
            "targets": [{**t, **pings[t["ip"]]} for t in TARGETS],
        }
        with _snap_lock:
            _snap["value"] = snap
        time.sleep(2)


# ---------- History (SQLite) ----------

def db_exec(sql, args=(), fetch=False):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        cur = conn.execute(sql, args)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db_exec("""CREATE TABLE IF NOT EXISTS samples (
        ts INTEGER PRIMARY KEY, cpu REAL, ram REAL, disk REAL,
        rx REAL, tx REAL, load1 REAL, ping REAL)""")


def _sample_loop():
    last_prune = 0.0
    while True:
        time.sleep(SAMPLE_INTERVAL)
        with _snap_lock:
            s = _snap["value"]
        if not s:
            continue
        try:
            db_exec("INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?,?)",
                    (s["ts"], s["cpu"], s["ram"], s["disk"], s["rx"], s["tx"],
                     s["load"][0], s["ping_avg"]))
            if time.time() - last_prune > 3600:
                db_exec("DELETE FROM samples WHERE ts < ?", (int(time.time()) - 8 * 86400,))
                last_prune = time.time()
        except Exception as e:
            print("history error:", type(e).__name__, flush=True)


def _r1(x):
    return None if x is None else round(x, 1)


# ---------- Telegram alerts ----------

def send_telegram(text):
    token = ALERTS.get("telegram_token")
    chat = ALERTS.get("chat_id")
    if not token or not chat:
        return False
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=10)
        return True
    except Exception as e:
        print("telegram error:", type(e).__name__, flush=True)
        return False


def describe(key, value, thr, down):
    if key.startswith("down:"):
        name = key[5:]
        return f"[{HOST}] Ping to {name} is {'down' if down else 'back up'}"
    label = {"cpu": "CPU", "ram": "Memory", "disk": "Disk"}[key]
    if down:
        return f"[{HOST}] {label} reached {value:.1f}% (threshold {thr}%)"
    return f"[{HOST}] {label} is back to normal ({value:.1f}%)"


def _alert_metrics(snap):
    m = {
        "cpu": (snap["cpu"], ALERTS.get("cpu", 90)),
        "ram": (snap["ram"], ALERTS.get("ram", 90)),
        "disk": (snap["disk"], ALERTS.get("disk", 90)),
    }
    for t in snap["targets"]:
        down = 1 if (t["loss"] is not None and t["loss"] >= 100) else 0
        m[f"down:{t['name']}"] = (down, 1)
    return m


def _alert_loop():
    while True:
        time.sleep(30)
        with _snap_lock:
            snap = _snap["value"]
        if not snap:
            continue
        now = time.time()
        cooldown = int(ALERTS.get("cooldown", 900))
        for key, (value, thr) in _alert_metrics(snap).items():
            st = _alert_state.setdefault(key, {"active": False, "notified": False, "last": 0.0})
            if value >= thr:
                if not st["active"]:
                    st["active"] = True
                    if now - st["last"] >= cooldown:
                        st["notified"] = send_telegram(describe(key, value, thr, True))
                        st["last"] = now
            elif st["active"]:
                st["active"] = False
                if st["notified"]:
                    send_telegram(describe(key, value, thr, False))
                    st["notified"] = False


# ---------- Routes ----------

@app.route("/api/stats")
@login_required
def stats():
    with _snap_lock:
        snap = _snap["value"]
    if not snap:
        return jsonify({"error": "warming_up"}), 503
    return jsonify(snap)


@app.route("/api/history")
@login_required
def history():
    key = request.args.get("range", "1h")
    if key not in RANGES:
        key = "1h"
    span, bucket = RANGES[key]
    since = int(time.time()) - span
    rows = db_exec(
        "SELECT (ts / ?) * ? AS t, AVG(cpu), AVG(ram), AVG(rx), AVG(tx), AVG(ping) "
        "FROM samples WHERE ts >= ? GROUP BY t ORDER BY t",
        (bucket, bucket, since), fetch=True)
    return jsonify({
        "range": key,
        "ts": [r[0] for r in rows],
        "cpu": [_r1(r[1]) for r in rows],
        "ram": [_r1(r[2]) for r in rows],
        "rx": [r[3] for r in rows],
        "tx": [r[4] for r in rows],
        "ping": [_r1(r[5]) for r in rows],
    })


def valid_host(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(HOST_RE.match(h))


@app.route("/api/check", methods=["POST"])
@login_required
def check():
    """Checks one IP or domain: ping plus an optional TCP port. One check every 3 seconds."""
    data = request.get_json(silent=True) or {}
    host = str(data.get("host", "")).strip()
    port_raw = str(data.get("port", "")).strip()
    if not valid_host(host):
        return jsonify({"error": "invalid_host"}), 400
    port = None
    if port_raw:
        if not port_raw.isdigit() or not (1 <= int(port_raw) <= 65535):
            return jsonify({"error": "invalid_port"}), 400
        port = int(port_raw)
    with _check_lock:
        if time.time() - _check_state["last"] < 3:
            return jsonify({"error": "rate"}), 429
        _check_state["last"] = time.time()

    ping = ping_host(host, count=3)
    res = {"host": host, "ping_avg": ping["avg"], "loss": ping["loss"],
           "port": port, "port_open": None, "port_ms": None}
    if port:
        t0 = time.time()
        try:
            with socket.create_connection((host, port), timeout=4):
                res["port_open"] = True
                res["port_ms"] = round((time.time() - t0) * 1000, 1)
        except Exception:
            res["port_open"] = False
    return jsonify(res)


# ---------- Translations (shared by login and dashboard) ----------

I18N_JS = """const I18N = {
en: {nav_overview:"Overview",nav_network:"Network",nav_resources:"Resources",nav_latency:"Latency",nav_history:"History",nav_tools:"Tools",
signout:"Sign out",connecting:"Connecting…",online:"Online",disconnected:"Disconnected",
h_overview:"Overview",p_overview:"Live server status, refreshed every 2 seconds",
cpu:"CPU",memory:"Memory",disk:"Disk",avg_latency:"Average latency",download:"Download",upload:"Upload",uptime:"Uptime",load:"Load",
loc_title:"Server location",loc_unknown:"Unknown",loc_unavail:"Location lookup unavailable (no internet or ip-api limit)",
services_title:"Services",no_services:"No services configured",
h_network:"Network",p_network:"Download and upload throughput, live",ch_traffic:"Traffic (KB/s)",
h_resources:"Resources",p_resources:"CPU and memory usage, and the processes using them",ch_cpu_mem:"CPU and memory (%)",
procs_title:"Top processes",sorted_cpu:"sorted by CPU",th_pid:"PID",th_name:"Name",th_cpu:"CPU %",th_mem:"Memory %",collecting:"Collecting data…",
h_latency:"Latency",p_latency:"Ping to remote targets: 5 packets every 30 seconds",lat_title:"Latency by country (ms)",
map_title:"Map",map_hint:"color = latency",targets_title:"Targets",
th_country:"Country",th_service:"Service",th_ip:"IP",th_latency:"Latency",th_jitter:"Jitter",th_loss:"Loss",timeout:"timeout",
h_history:"History",p_history:"Stored every 60 seconds, kept for 8 days",range:"Range",ch_history_cpu:"CPU and memory (%)",ch_history_net:"Network (KB/s)",
h_tools:"Tools",p_tools:"Check an IP address or domain from this server. One check every 3 seconds.",
tools_host:"IP address or domain",tools_port:"TCP port (optional)",run_check:"Run check",
r_target:"Target",r_ping:"Average ping",r_loss:"Packet loss",r_port:"TCP port",not_tested:"not tested",open:"open",closed:"closed",
e_invalid_host:"Enter a valid IP address or domain name.",e_invalid_port:"Port must be between 1 and 65535.",
e_rate:"Please wait a few seconds between checks.",e_request:"Request failed. Check the server connection.",
e_invalid:"Invalid username or password",e_locked:"Too many failed attempts. Try again in a minute.",
ch_cpu:"CPU %",ch_mem:"Memory %",ch_down:"Download",ch_up:"Upload",
st_active:"active",st_inactive:"inactive",st_failed:"failed",st_unknown:"unknown",
l_eyebrow:"Control · Clarity · Confidence",l_hero1:"Your servers.",l_hero2:"In real time.",
l_lead:"Health, network activity, latency and services of your server in one clean dashboard.",
l_f1_t:"Live system telemetry",l_f1_s:"CPU, memory, disk, uptime and network signals",
l_f2_t:"Protected dashboard",l_f2_s:"Private access with rate-limited sign-in",
l_secure:"Secure session",l_title:"Sign in to continue",l_note:"Enter your administrator credentials.",
l_user:"Username",l_pass:"Password",l_signin:"Sign in",l_brand_sub:"SERVER MONITORING",
footer:"ServerPulse v{v} · by ArshamSmok"},
fa: {nav_overview:"نمای کلی",nav_network:"شبکه",nav_resources:"منابع",nav_latency:"تأخیر",nav_history:"تاریخچه",nav_tools:"ابزارها",
signout:"خروج",connecting:"در حال اتصال…",online:"آنلاین",disconnected:"قطع اتصال",
h_overview:"نمای کلی",p_overview:"وضعیت زنده سرور، هر ۲ ثانیه به‌روز می‌شود",
cpu:"پردازنده",memory:"حافظه",disk:"دیسک",avg_latency:"میانگین تأخیر",download:"دریافت",upload:"ارسال",uptime:"مدت روشن بودن",load:"بار",
loc_title:"موقعیت سرور",loc_unknown:"نامشخص",loc_unavail:"دریافت موقعیت ممکن نیست (اینترنت یا محدودیت ip-api)",
services_title:"سرویس‌ها",no_services:"سرویسی تنظیم نشده است",
h_network:"شبکه",p_network:"سرعت دریافت و ارسال به‌صورت زنده",ch_traffic:"ترافیک (KB/s)",
h_resources:"منابع",p_resources:"مصرف پردازنده و حافظه و فرایندهای پرمصرف",ch_cpu_mem:"پردازنده و حافظه (%)",
procs_title:"فرایندهای پرمصرف",sorted_cpu:"مرتب‌شده بر اساس CPU",th_pid:"PID",th_name:"نام",th_cpu:"CPU %",th_mem:"حافظه %",collecting:"در حال جمع‌آوری…",
h_latency:"تأخیر",p_latency:"پینگ به مقصدهای خارجی: ۵ بسته هر ۳۰ ثانیه",lat_title:"تأخیر به تفکیک کشور (ms)",
map_title:"نقشه",map_hint:"رنگ = تأخیر",targets_title:"مقصدها",
th_country:"کشور",th_service:"سرویس",th_ip:"IP",th_latency:"تأخیر",th_jitter:"جیتر",th_loss:"افت بسته",timeout:"بدون پاسخ",
h_history:"تاریخچه",p_history:"هر ۶۰ ثانیه ذخیره می‌شود و ۸ روز نگه داشته می‌شود",range:"بازه",
ch_history_cpu:"پردازنده و حافظه (%)",ch_history_net:"شبکه (KB/s)",
h_tools:"ابزارها",p_tools:"بررسی IP یا دامنه از این سرور. هر ۳ ثانیه یک بررسی.",
tools_host:"آدرس IP یا دامنه",tools_port:"پورت TCP (اختیاری)",run_check:"اجرای بررسی",
r_target:"مقصد",r_ping:"میانگین پینگ",r_loss:"افت بسته",r_port:"پورت TCP",not_tested:"انجام نشد",open:"باز",closed:"بسته",
e_invalid_host:"آدرس IP یا دامنه معتبر وارد کنید.",e_invalid_port:"پورت باید بین ۱ و ۶۵۵۳۵ باشد.",
e_rate:"بین بررسی‌ها چند ثانیه صبر کنید.",e_request:"درخواست ناموفق بود. اتصال سرور را بررسی کنید.",
e_invalid:"نام کاربری یا رمز عبور اشتباه است",e_locked:"تلاش‌های ناموفق زیاد بود. یک دقیقه دیگر امتحان کنید.",
ch_cpu:"پردازنده %",ch_mem:"حافظه %",ch_down:"دریافت",ch_up:"ارسال",
st_active:"فعال",st_inactive:"غیرفعال",st_failed:"خطا",st_unknown:"نامشخص",
l_eyebrow:"کنترل · شفافیت · اطمینان",l_hero1:"سرورهای شما.",l_hero2:"لحظه به لحظه.",
l_lead:"سلامت، فعالیت شبکه، تأخیر و سرویس‌های سرور خود را در یک داشبورد ساده ببینید.",
l_f1_t:"تله‌متری زنده سیستم",l_f1_s:"پردازنده، حافظه، دیسک، مدت روشن بودن و وضعیت شبکه",
l_f2_t:"داشبورد محافظت‌شده",l_f2_s:"دسترسی خصوصی با محدودیت تعداد ورود",
l_secure:"نشست امن",l_title:"برای ادامه وارد شوید",l_note:"اطلاعات مدیر را وارد کنید.",
l_user:"نام کاربری",l_pass:"رمز عبور",l_signin:"ورود",l_brand_sub:"پایش سرور",
footer:"ServerPulse نسخه {v} · ساخته‌شده توسط ArshamSmok"}
};"""

# ---------- Styles ----------

_TOPO_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' width='600' height='400'>"
    "<g stroke='#22d3ee' stroke-opacity='0.18' fill='none' stroke-width='1'>"
    "<path d='M60 80 L180 140 L300 60 L420 150 L540 90'/>"
    "<path d='M180 140 L240 280 L380 320 L420 150'/>"
    "<path d='M60 80 L40 230 L240 280'/>"
    "<path d='M300 60 L330 220 L380 320 L540 90 L560 300'/>"
    "</g><g fill='#22d3ee' fill-opacity='0.45'>"
    + "".join(f"<circle cx='{x}' cy='{y}' r='2.5'/>" for x, y in
              [(60, 80), (180, 140), (300, 60), (420, 150), (540, 90),
               (240, 280), (380, 320), (40, 230), (330, 220), (560, 300)])
    + "</g></svg>"
)

if BACKGROUND:
    BG_LAYER = ('background-image:url("%s");background-size:cover;'
                'background-position:center;filter:brightness(.5)' % BACKGROUND)
else:
    BG_LAYER = ('background-image:url("data:image/svg+xml;utf8,%s");'
                'background-size:600px 400px' % urllib.parse.quote(_TOPO_SVG))

BASE_CSS = """
  :root{--text:#e6edf3;--muted:#8b98a9;--accent:#22d3ee;--accent2:#5eead4;--good:#34d399;--line:rgba(148,163,184,.12)}
  *{box-sizing:border-box}
  html{min-height:100%;background:#070c17;color-scheme:dark}
  html[lang=fa] body{font-family:Vazirmatn,Inter,system-ui,sans-serif}
  body{margin:0;min-height:100vh;color:var(--text);font:14px/1.5 Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
  body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;opacity:.85;{{bg}}}
  body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
    background:radial-gradient(ellipse at 15% 0%,rgba(34,211,238,.10),transparent 55%),
      radial-gradient(ellipse at 100% 100%,rgba(94,234,212,.06),transparent 50%),
      linear-gradient(180deg,rgba(7,12,23,.55),rgba(7,12,23,.92))}
  .glass{background:linear-gradient(180deg,rgba(255,255,255,.07),rgba(255,255,255,.025));
    -webkit-backdrop-filter:blur(16px) saturate(120%);backdrop-filter:blur(16px) saturate(120%);
    box-shadow:0 18px 40px rgba(0,0,0,.35);border-radius:22px}
  .lift{transition:transform .25s ease,box-shadow .25s ease}
  .lift:hover{transform:translateY(-2px);box-shadow:0 22px 48px rgba(0,0,0,.45)}
  .inp{width:100%;padding:11px 14px;border:0;border-radius:12px;color:#f8fafc;font:inherit;background:rgba(255,255,255,.06);box-shadow:inset 0 0 0 1px rgba(255,255,255,.04)}
  .inp:focus{outline:none;box-shadow:0 0 0 2px rgba(34,211,238,.45)}
  .lang{display:inline-flex;padding:3px;border-radius:10px;background:rgba(255,255,255,.06)}
  .lang button{border:0;background:transparent;color:var(--muted);padding:5px 11px;border-radius:8px;font:inherit;font-size:12px;cursor:pointer}
  .lang button.on{background:rgba(34,211,238,.14);color:#ecfeff}
  .badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--accent2);padding:5px 10px;border-radius:999px;background:rgba(94,234,212,.1)}
"""

LOGIN_CSS = """{{base}}
  body{display:grid;place-items:center;padding:28px}
  .topbar{position:fixed;top:18px;inset-inline-end:24px}
  .wrap{width:min(1080px,100%);display:grid;grid-template-columns:1.1fr .9fr;gap:56px;align-items:center}
  .brand{display:flex;align-items:center;gap:12px;font-weight:700;font-size:17px}
  .brand small{display:block;font-size:10px;letter-spacing:.2em;color:var(--muted);font-weight:500}
  .mark{width:12px;height:12px;border-radius:50%;background:var(--accent);box-shadow:0 0 18px var(--accent)}
  .eyebrow{margin-top:64px;color:var(--accent2);font-size:12px;letter-spacing:.14em;text-transform:uppercase;font-weight:600}
  h1.hero{margin:14px 0;font-size:46px;line-height:1.08;font-weight:700;letter-spacing:-.02em}
  h1.hero span.acc{color:var(--accent)}
  .lead{color:var(--muted);max-width:520px;font-size:15px;margin:0}
  .features{margin-top:34px;border-top:1px solid var(--line)}
  .feat{padding:16px 0;border-bottom:1px solid var(--line)}
  .feat b{display:block;font-weight:600}
  .feat span{color:var(--muted);font-size:13px}
  .form{padding:34px 32px}
  .form h2{margin:14px 0 4px;font-size:24px;font-weight:700}
  .form .note{color:var(--muted);margin:0 0 22px;font-size:13px}
  label{display:block;font-size:12.5px;color:var(--muted);margin:16px 0 7px}
  .primary{margin-top:24px;width:100%;padding:13px;border:0;border-radius:12px;color:#06202a;font:inherit;font-weight:600;background:var(--accent2);cursor:pointer;transition:filter .2s}
  .primary:hover{filter:brightness(1.08)}
  .err{color:#fca5a5;font-size:13px;margin-top:12px;min-height:18px}
  @media (max-width:860px){.wrap{grid-template-columns:1fr;gap:28px}h1.hero{font-size:32px}.eyebrow{margin-top:24px}}
"""

PAGE_CSS = """{{base}}
  .app{display:grid;grid-template-columns:236px minmax(0,1fr);min-height:100vh}
  .sidebar{position:sticky;top:14px;align-self:start;height:calc(100vh - 28px);margin:14px;padding:24px 16px;display:flex;flex-direction:column;gap:24px}
  .brand{font-weight:700;font-size:16px;padding:0 10px}
  .brand b{color:var(--accent);font-weight:700}
  .nav{display:flex;flex-direction:column;gap:4px}
  .nav a{display:flex;gap:12px;align-items:center;color:var(--muted);text-decoration:none;padding:10px 12px;border-radius:12px;font-size:13.5px;transition:background .2s,color .2s}
  .nav a i{font-style:normal;font-size:11px;color:#55657a;width:20px;font-variant-numeric:tabular-nums}
  .nav a:hover{color:var(--text);background:rgba(255,255,255,.05)}
  .nav a.active{color:#ecfeff;background:rgba(34,211,238,.12)}
  .nav a.active i{color:var(--accent)}
  .side-foot{margin-top:auto;padding:0 10px;font-size:12.5px;color:var(--muted);display:flex;flex-direction:column;gap:12px}
  .side-foot a{color:var(--muted);text-decoration:none}
  .side-foot a:hover{color:var(--text)}
  .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--good);margin-inline-end:6px}
  main{padding:26px 30px 8px;min-width:0}
  .head{margin:0 0 20px}
  .head h1{margin:0;font-size:24px;font-weight:700}
  .head p{margin:4px 0 0;color:var(--muted);font-size:13px}
  .page{display:none}
  .page.show{display:block}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:14px}
  .card{padding:18px 20px}
  .label{font-size:12.5px;color:var(--muted)}
  .value{font-size:26px;font-weight:600;margin-top:8px;direction:ltr;text-align:start;font-variant-numeric:tabular-nums}
  .value.sm{font-size:18px}
  .meter{height:4px;background:rgba(255,255,255,.07);border-radius:99px;margin-top:14px;overflow:hidden}
  .meter i{display:block;height:100%;width:0;background:var(--accent);border-radius:99px;transition:width .6s ease}
  .hint{font-size:12px;color:var(--muted);margin-top:6px;direction:ltr;text-align:start}
  .panel{padding:20px 22px;margin-bottom:14px}
  .panel h3{margin:0 0 14px;font-size:14px;font-weight:600;display:flex;justify-content:space-between;align-items:center;gap:12px}
  .panel h3 small{color:var(--muted);font-weight:400;font-size:12px}
  .row2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
  .row2 .panel{margin-bottom:0}
  .chart{position:relative;height:300px}
  .chips{display:flex;flex-wrap:wrap;gap:8px}
  .chip{display:inline-flex;align-items:center;padding:7px 12px;border-radius:999px;background:rgba(255,255,255,.05);font-size:12.5px}
  .toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
  .toolbar h2{margin:0;font-size:15px;font-weight:600}
  .seg{display:inline-flex;padding:4px;border-radius:12px;background:rgba(255,255,255,.05)}
  .seg button{border:0;background:transparent;color:var(--muted);padding:6px 14px;border-radius:9px;font:inherit;font-size:12.5px;cursor:pointer}
  .seg button.on{background:rgba(34,211,238,.14);color:#ecfeff}
  #map{height:320px;border-radius:16px;overflow:hidden}
  .leaflet-container{background:#0b1220;font-family:inherit}
  .leaflet-tile{filter:grayscale(.8) brightness(.55) contrast(1.1)}
  .table-wrap{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px 8px;text-align:start;border-bottom:1px solid var(--line);white-space:nowrap}
  th{color:var(--muted);font-weight:500;font-size:12px}
  .num{direction:ltr;unicode-bidi:isolate}
  .code{display:inline-block;min-width:30px;color:var(--accent);font-weight:600;font-size:12px}
  .pd{display:inline-block;width:8px;height:8px;border-radius:50%;margin-inline-end:8px;vertical-align:middle}
  .form-row{display:grid;grid-template-columns:minmax(0,1fr) 140px auto;gap:12px;align-items:end}
  .form-row label{margin:0 0 7px}
  .results{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:18px}
  .results div{padding:16px 18px;border-radius:16px;background:rgba(255,255,255,.04)}
  .results b{display:block;font-size:20px;font-weight:600;margin-top:6px;direction:ltr;text-align:start;font-variant-numeric:tabular-nums;word-break:break-all}
  .btn{padding:11px 18px;border:0;border-radius:12px;background:var(--accent2);color:#06202a;font:inherit;font-weight:600;cursor:pointer;transition:filter .2s}
  .btn:hover{filter:brightness(1.08)}
  .btn:disabled{opacity:.5;cursor:default}
  .msg{color:#fca5a5;font-size:13px;margin-top:12px;min-height:18px}
  footer{color:var(--muted);font-size:12px;padding:8px 0 22px}
  @media (max-width:980px){
    .app{grid-template-columns:1fr}
    .sidebar{position:sticky;top:0;z-index:5;height:auto;margin:0;border-radius:0;flex-direction:row;align-items:center;flex-wrap:wrap;padding:12px 14px}
    .nav{flex-direction:row;flex-wrap:wrap}
    .side-foot{margin:0 0 0 auto;flex-direction:row;align-items:center;flex-wrap:wrap}
    main{padding:18px}
    .row2{grid-template-columns:1fr}
    .form-row{grid-template-columns:1fr}
  }
  @media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"""

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ServerPulse</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vazirmatn@33.0.3/Vazirmatn-font-face.css">
<style>
{{login_css}}
</style>
</head>
<body>
<div class="topbar"><div class="lang"><button data-lang="en">EN</button><button data-lang="fa">FA</button></div></div>
<div class="wrap">
  <div>
    <div class="brand"><span class="mark"></span><div>ServerPulse<small data-i18n="l_brand_sub"></small></div></div>
    <div class="eyebrow" data-i18n="l_eyebrow"></div>
    <h1 class="hero"><span data-i18n="l_hero1"></span><br><span class="acc" data-i18n="l_hero2"></span></h1>
    <p class="lead" data-i18n="l_lead"></p>
    <div class="features">
      <div class="feat"><b data-i18n="l_f1_t"></b><span data-i18n="l_f1_s"></span></div>
      <div class="feat"><b data-i18n="l_f2_t"></b><span data-i18n="l_f2_s"></span></div>
    </div>
  </div>
  <form class="glass form" method="post" action="login">
    <span class="badge" data-i18n="l_secure"></span>
    <h2 data-i18n="l_title"></h2>
    <p class="note" data-i18n="l_note"></p>
    <label for="u" data-i18n="l_user"></label>
    <input id="u" class="inp" name="username" autocomplete="username" required autofocus>
    <label for="p" data-i18n="l_pass"></label>
    <input id="p" class="inp" name="password" type="password" autocomplete="current-password" required>
    <button class="primary" type="submit" data-i18n="l_signin"></button>
    <div class="err" id="err" data-err="{{error}}"></div>
  </form>
</div>
<script>
{{i18n}}
let LANG = localStorage.getItem("sp-lang") || "en";
const T = k => (I18N[LANG] && I18N[LANG][k]) || I18N.en[k] || k;
function applyLang() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = T(el.dataset.i18n));
  document.querySelectorAll(".lang button").forEach(b => b.classList.toggle("on", b.dataset.lang === LANG));
  const e = document.getElementById("err");
  if (e.dataset.err) e.textContent = T("e_" + e.dataset.err);
}
document.querySelectorAll(".lang button").forEach(b => b.addEventListener("click", () => {
  LANG = b.dataset.lang;
  localStorage.setItem("sp-lang", LANG);
  applyLang();
}));
applyLang();
</script>
</body>
</html>"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ServerPulse</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vazirmatn@33.0.3/Vazirmatn-font-face.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>
{{page_css}}
</style>
</head>
<body>
<div class="app">
  <aside class="glass sidebar">
    <div class="brand">Server<b>Pulse</b></div>
    <nav class="nav">
      <a href="#overview" data-p="overview"><i>01</i><span data-i18n="nav_overview"></span></a>
      <a href="#network" data-p="network"><i>02</i><span data-i18n="nav_network"></span></a>
      <a href="#resources" data-p="resources"><i>03</i><span data-i18n="nav_resources"></span></a>
      <a href="#latency" data-p="latency"><i>04</i><span data-i18n="nav_latency"></span></a>
      <a href="#history" data-p="history"><i>05</i><span data-i18n="nav_history"></span></a>
      <a href="#tools" data-p="tools"><i>06</i><span data-i18n="nav_tools"></span></a>
    </nav>
    <div class="side-foot">
      <div id="status"></div>
      <div class="lang"><button data-lang="en">EN</button><button data-lang="fa">FA</button></div>
      <a href="logout" data-i18n="signout"></a>
    </div>
  </aside>

  <main>
    <section class="page" id="overview">
      <div class="head"><h1 data-i18n="h_overview"></h1><p data-i18n="p_overview"></p></div>
      <div class="grid">
        <div class="glass lift card"><div class="label" data-i18n="cpu"></div><div class="value" id="cpu">–</div><div class="meter"><i id="cpuBar"></i></div></div>
        <div class="glass lift card"><div class="label" data-i18n="memory"></div><div class="value" id="ram">–</div><div class="meter"><i id="ramBar"></i></div></div>
        <div class="glass lift card"><div class="label" data-i18n="disk"></div><div class="value" id="disk">–</div><div class="meter"><i id="diskBar"></i></div></div>
        <div class="glass lift card"><div class="label" data-i18n="avg_latency"></div><div class="value" id="avgPing">–</div></div>
        <div class="glass lift card"><div class="label" data-i18n="download"></div><div class="value" id="rx">–</div></div>
        <div class="glass lift card"><div class="label" data-i18n="upload"></div><div class="value" id="tx">–</div></div>
        <div class="glass lift card"><div class="label" data-i18n="uptime"></div><div class="value sm" id="uptime">–</div><div class="hint" id="load"></div></div>
      </div>
      <div class="row2">
        <div class="glass panel"><h3 data-i18n="loc_title"></h3><div class="value sm" id="loc">–</div><div class="hint" id="isp"></div></div>
        <div class="glass panel"><h3 data-i18n="services_title"></h3><div class="chips" id="svcList"></div></div>
      </div>
    </section>

    <section class="page" id="network">
      <div class="head"><h1 data-i18n="h_network"></h1><p data-i18n="p_network"></p></div>
      <div class="glass panel"><h3 data-i18n="ch_traffic"></h3><div class="chart"><canvas id="netChart"></canvas></div></div>
    </section>

    <section class="page" id="resources">
      <div class="head"><h1 data-i18n="h_resources"></h1><p data-i18n="p_resources"></p></div>
      <div class="glass panel"><h3 data-i18n="ch_cpu_mem"></h3><div class="chart"><canvas id="cpuChart"></canvas></div></div>
      <div class="glass panel">
        <h3><span data-i18n="procs_title"></span><small data-i18n="sorted_cpu"></small></h3>
        <div class="table-wrap">
          <table>
            <thead><tr><th data-i18n="th_pid"></th><th data-i18n="th_name"></th><th data-i18n="th_cpu"></th><th data-i18n="th_mem"></th></tr></thead>
            <tbody id="procBody"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="page" id="latency">
      <div class="head"><h1 data-i18n="h_latency"></h1><p data-i18n="p_latency"></p></div>
      <div class="glass panel"><h3 data-i18n="lat_title"></h3><div class="chart"><canvas id="pingChart"></canvas></div></div>
      <div class="row2">
        <div class="glass panel"><h3><span data-i18n="map_title"></span><small data-i18n="map_hint"></small></h3><div id="map"></div></div>
        <div class="glass panel">
          <h3 data-i18n="targets_title"></h3>
          <div class="table-wrap">
            <table>
              <thead><tr><th data-i18n="th_country"></th><th data-i18n="th_service"></th><th data-i18n="th_ip"></th><th data-i18n="th_latency"></th><th data-i18n="th_jitter"></th><th data-i18n="th_loss"></th></tr></thead>
              <tbody id="pingBody"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <section class="page" id="history">
      <div class="head"><h1 data-i18n="h_history"></h1><p data-i18n="p_history"></p></div>
      <div class="toolbar">
        <h2 data-i18n="range"></h2>
        <div class="seg">
          <button data-r="1h" class="on">1h</button>
          <button data-r="24h">24h</button>
          <button data-r="7d">7d</button>
        </div>
      </div>
      <div class="row2">
        <div class="glass panel"><h3 data-i18n="ch_history_cpu"></h3><div class="chart"><canvas id="histCpu"></canvas></div></div>
        <div class="glass panel"><h3 data-i18n="ch_history_net"></h3><div class="chart"><canvas id="histNet"></canvas></div></div>
      </div>
    </section>

    <section class="page" id="tools">
      <div class="head"><h1 data-i18n="h_tools"></h1><p data-i18n="p_tools"></p></div>
      <div class="glass panel">
        <form id="checkForm" class="form-row" autocomplete="off">
          <div><label for="host" data-i18n="tools_host"></label><input id="host" class="inp" required></div>
          <div><label for="port" data-i18n="tools_port"></label><input id="port" class="inp" inputmode="numeric"></div>
          <button id="checkBtn" class="btn" type="submit" data-i18n="run_check"></button>
        </form>
        <div class="msg" id="checkMsg"></div>
        <div class="results" id="results" style="display:none">
          <div><span class="label" data-i18n="r_target"></span><b id="resHost">–</b></div>
          <div><span class="label" data-i18n="r_ping"></span><b id="resPing">–</b></div>
          <div><span class="label" data-i18n="r_loss"></span><b id="resLoss">–</b></div>
          <div><span class="label" data-i18n="r_port"></span><b id="resPort">–</b></div>
        </div>
      </div>
    </section>

    <footer id="footer"></footer>
  </main>
</div>

<script>
{{i18n}}
const $ = id => document.getElementById(id);
const VERSION = "{{version}}";
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const N = 60;
const labels = Array(N).fill("");
const C = { cpu: "#22d3ee", ram: "#a78bfa", rx: "#5eead4", tx: "#fbbf24" };
const PALETTE = ["#22d3ee", "#a78bfa", "#f472b6", "#fbbf24", "#5eead4", "#94a3b8", "#60a5fa", "#fb7185", "#c084fc", "#fcd34d"];
const ST = { active: "#34d399", inactive: "#64748b", failed: "#f87171", activating: "#fbbf24" };
let LANG = localStorage.getItem("sp-lang") || "en";
let LAST = null, ONLINE = null, lastSig = "", lastSvc = "", inFlight = false, histRange = "1h";
const T = k => (I18N[LANG] && I18N[LANG][k]) || I18N.en[k] || k;
const cname = t => (LANG === "fa" && t.country_fa) ? t.country_fa : t.country;
const pingColor = ms => ms === null ? "#64748b" : ms < 80 ? "#34d399" : ms < 200 ? "#fbbf24" : "#f87171";
const pingText = ms => ms === null ? T("timeout") : ms + " ms";

const baseOpts = () => ({
  animation: false, responsive: true, maintainAspectRatio: false,
  interaction: { mode: "index", intersect: false },
  scales: {
    x: { display: false },
    y: { beginAtZero: true, grid: { color: "rgba(148,163,184,.08)" }, ticks: { color: "#8b98a9" } }
  },
  plugins: { legend: { labels: { color: "#cbd5e1", boxWidth: 10, font: { size: 12 } } } }
});
const line = (label, color, data) => ({
  label, data, borderColor: color, backgroundColor: color + "18", fill: true,
  tension: .35, pointRadius: 0, borderWidth: 2, spanGaps: true
});
const blank = () => Array(N).fill(null);

const cpuChart = new Chart($("cpuChart"), {
  type: "line", data: { labels, datasets: [line(T("ch_cpu"), C.cpu, blank()), line(T("ch_mem"), C.ram, blank())] }, options: baseOpts()
});
const netChart = new Chart($("netChart"), {
  type: "line", data: { labels, datasets: [line(T("ch_down"), C.rx, blank()), line(T("ch_up"), C.tx, blank())] }, options: baseOpts()
});
let pingChart = null;
function ensurePingChart(targets) {
  if (pingChart) return;
  pingChart = new Chart($("pingChart"), {
    type: "line",
    data: { labels, datasets: targets.map((t, i) => ({ ...line(cname(t), PALETTE[i % PALETTE.length], blank()), fill: false })) },
    options: baseOpts()
  });
}
const histCpu = new Chart($("histCpu"), {
  type: "line", data: { labels: [], datasets: [line(T("ch_cpu"), C.cpu, []), line(T("ch_mem"), C.ram, [])] }, options: baseOpts()
});
const histNet = new Chart($("histNet"), {
  type: "line", data: { labels: [], datasets: [line(T("ch_down"), C.rx, []), line(T("ch_up"), C.tx, [])] }, options: baseOpts()
});

function relabel() {
  const set = (ch, keys) => { keys.forEach((k, i) => ch.data.datasets[i].label = T(k)); ch.update("none"); };
  set(cpuChart, ["ch_cpu", "ch_mem"]);
  set(netChart, ["ch_down", "ch_up"]);
  set(histCpu, ["ch_cpu", "ch_mem"]);
  set(histNet, ["ch_down", "ch_up"]);
}

function fmtLabel(ts, range) {
  const d = new Date(ts * 1000), loc = LANG === "fa" ? "fa-IR" : "en-US";
  return range === "7d"
    ? d.toLocaleString(loc, { month: "short", day: "numeric", hour: "2-digit" })
    : d.toLocaleTimeString(loc, { hour: "2-digit", minute: "2-digit" });
}
async function loadHistory() {
  if (document.hidden) return;
  try {
    const r = await fetch("api/history?range=" + histRange, { cache: "no-store" });
    if (r.status === 401) { location.href = "login"; return; }
    const h = await r.json();
    const hl = h.ts.map(t => fmtLabel(t, histRange));
    histCpu.data.labels = hl;
    histCpu.data.datasets[0].data = h.cpu;
    histCpu.data.datasets[1].data = h.ram;
    histCpu.update();
    histNet.data.labels = hl;
    histNet.data.datasets[0].data = h.rx.map(v => v === null ? null : v / 1024);
    histNet.data.datasets[1].data = h.tx.map(v => v === null ? null : v / 1024);
    histNet.update();
  } catch (e) { /* keep the previous charts on error */ }
}
document.querySelectorAll(".seg button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".seg button").forEach(x => x.classList.remove("on"));
  b.classList.add("on");
  histRange = b.dataset.r;
  loadHistory();
}));

const map = L.map("map").setView([20, 0], 2);
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 6, attribution: "© OpenStreetMap" }).addTo(map);
const mapLayer = L.layerGroup().addTo(map);
let fitted = false;

function renderMap(sv, targets) {
  mapLayer.clearLayers();
  const pts = [];
  const hasServer = !!(sv && sv.lat != null);
  if (hasServer) {
    pts.push([sv.lat, sv.lon]);
    L.circleMarker([sv.lat, sv.lon], { radius: 7, color: "#fff", weight: 2, fillColor: "#34d399", fillOpacity: 1 })
      .bindTooltip(sv.city + ", " + sv.country).addTo(mapLayer);
  }
  targets.forEach(t => {
    if (t.lat == null) return;
    const c = pingColor(t.avg);
    pts.push([t.lat, t.lng]);
    if (hasServer) {
      L.polyline([[sv.lat, sv.lon], [t.lat, t.lng]], { color: c, weight: 1.5, opacity: .55, dashArray: "6 6" }).addTo(mapLayer);
    }
    L.circleMarker([t.lat, t.lng], { radius: 6, color: "#fff", weight: 2, fillColor: c, fillOpacity: 1 })
      .bindTooltip(cname(t) + ": " + pingText(t.avg)).addTo(mapLayer);
  });
  if (!fitted && pts.length > 1) {
    map.fitBounds(pts, { padding: [30, 30], maxZoom: 4 });
    fitted = true;
  }
}

function renderTable(targets) {
  $("pingBody").innerHTML = targets.map(t =>
    `<tr><td><span class="code">${esc(t.code)}</span>${esc(cname(t))}</td><td>${esc(t.name)}</td>` +
    `<td class="num">${esc(t.ip)}</td>` +
    `<td class="num"><span class="pd" style="background:${pingColor(t.avg)}"></span>${pingText(t.avg)}</td>` +
    `<td class="num">${t.jitter === null ? "–" : t.jitter + " ms"}</td>` +
    `<td class="num">${t.loss === null ? "–" : t.loss.toFixed(1) + "%"}</td></tr>`
  ).join("");
}

function renderServices(list) {
  $("svcList").innerHTML = list.length
    ? list.map(s => {
        const st = T("st_" + s.state) || s.state;
        return `<span class="chip"><span class="pd" style="margin-inline-end:8px;background:${ST[s.state] || "#64748b"}"></span>${esc(s.name)} · ${esc(st)}</span>`;
      }).join("")
    : `<span class="hint">${T("no_services")}</span>`;
}

function renderProcs(list) {
  $("procBody").innerHTML = list.length
    ? list.map(p => `<tr><td class="num">${p.pid}</td><td>${esc(p.name)}</td><td class="num">${p.cpu.toFixed(1)}</td><td class="num">${p.mem.toFixed(1)}</td></tr>`).join("")
    : `<tr><td colspan="4">${T("collecting")}</td></tr>`;
}

function renderLoc(sv) {
  if (!sv) {
    $("loc").textContent = T("loc_unknown");
    $("isp").textContent = T("loc_unavail");
    return;
  }
  $("loc").textContent = sv.city + ", " + sv.country;
  $("isp").textContent = "IP " + sv.ip + " · " + sv.isp;
}

const fmtRate = b => {
  const u = ["B/s", "KB/s", "MB/s", "GB/s"]; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(1) + " " + u[i];
};
const fmtUptime = s => {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return LANG === "fa" ? `${d} روز ${h} ساعت ${m} دقیقه` : `${d}d ${h}h ${m}m`;
};
const setBar = (id, pct) => $(id).style.width = Math.min(pct, 100) + "%";
const push = (chart, vals) => {
  chart.data.datasets.forEach((d, i) => { d.data.push(vals[i]); d.data.shift(); });
  chart.update("none");
};
function setStatus(online) {
  ONLINE = online;
  const dot = online === null ? "#64748b" : online ? "#34d399" : "#f87171";
  const text = online === null ? T("connecting") : online ? T("online") : T("disconnected");
  $("status").innerHTML = `<span class="dot" style="background:${dot}"></span>${text}`;
}

// Redraws text and the tables/map from the latest snapshot (also used after a language change)
function paint(s, force) {
  $("cpu").textContent = s.cpu.toFixed(1) + "%";
  $("ram").textContent = s.ram.toFixed(1) + "%";
  $("disk").textContent = s.disk.toFixed(1) + "%";
  setBar("cpuBar", s.cpu); setBar("ramBar", s.ram); setBar("diskBar", s.disk);
  $("rx").textContent = fmtRate(s.rx);
  $("tx").textContent = fmtRate(s.tx);
  $("uptime").textContent = fmtUptime(s.uptime);
  $("load").textContent = T("load") + " " + s.load.join(" · ");
  $("avgPing").textContent = s.ping_avg === null ? T("timeout") : s.ping_avg.toFixed(1) + " ms";
  renderServices(s.services);
  renderProcs(s.top);
  renderLoc(s.server);
  const sig = JSON.stringify([s.targets.map(t => [t.avg, t.jitter, t.loss]), s.server]);
  if (force || sig !== lastSig) {
    renderTable(s.targets);
    renderMap(s.server, s.targets);
    lastSig = sig;
  }
  if (pingChart) {
    pingChart.data.datasets.forEach((d, i) => { if (s.targets[i]) d.label = cname(s.targets[i]); });
    pingChart.update("none");
  }
}

function applyLang() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = T(el.dataset.i18n));
  document.querySelectorAll(".lang button").forEach(b => b.classList.toggle("on", b.dataset.lang === LANG));
  $("footer").textContent = T("footer").replace("{v}", VERSION);
  relabel();
  setStatus(ONLINE);
  if (LAST) paint(LAST, true);
  loadHistory();
}
document.querySelectorAll(".lang button").forEach(b => b.addEventListener("click", () => {
  LANG = b.dataset.lang;
  localStorage.setItem("sp-lang", LANG);
  applyLang();
}));

const pages = ["overview", "network", "resources", "latency", "history", "tools"];
function showPage(name) {
  if (!pages.includes(name)) name = "overview";
  document.querySelectorAll(".page").forEach(p => p.classList.toggle("show", p.id === name));
  document.querySelectorAll(".nav a").forEach(a => a.classList.toggle("active", a.dataset.p === name));
  if (name === "latency") setTimeout(() => map.invalidateSize(), 60);
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", () => showPage(location.hash.slice(1)));

$("checkForm").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = $("checkBtn");
  btn.disabled = true;
  $("checkMsg").textContent = "";
  try {
    const r = await fetch("api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host: $("host").value, port: $("port").value })
    });
    const d = await r.json();
    if (!r.ok) { $("checkMsg").textContent = T("e_" + (d.error === "rate" ? "rate" : d.error)); return; }
    $("resHost").textContent = d.host;
    $("resPing").textContent = d.ping_avg === null ? T("timeout") : d.ping_avg + " ms";
    $("resLoss").textContent = d.loss.toFixed(0) + "%";
    $("resPort").textContent = d.port === null ? T("not_tested")
      : d.port_open ? T("open") + " · " + d.port_ms + " ms" : T("closed");
    $("results").style.display = "grid";
  } catch (err) {
    $("checkMsg").textContent = T("e_request");
  } finally {
    btn.disabled = false;
  }
});

async function tick() {
  if (document.hidden || inFlight) return;
  inFlight = true;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch("api/stats", { cache: "no-store", signal: ctrl.signal });
    if (r.status === 401) { location.href = "login"; return; }
    if (r.status === 503) return;
    const s = await r.json();
    LAST = s;
    ensurePingChart(s.targets);
    push(cpuChart, [s.cpu, s.ram]);
    push(netChart, [s.rx / 1024, s.tx / 1024]);
    push(pingChart, s.targets.map(t => t.avg));
    paint(s, false);
    setStatus(true);
  } catch (e) {
    setStatus(false);
  } finally {
    clearTimeout(timer);
    inFlight = false;
  }
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { tick(); loadHistory(); }
});
applyLang();
showPage(location.hash.slice(1) || "overview");
setInterval(tick, 2000);
setInterval(loadHistory, 60000);
tick();
</script>
</body>
</html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if time.time() < _login_state["until"]:
            error = "locked"
        else:
            user = request.form.get("username", "")
            pwd = request.form.get("password", "")
            if user == CFG["username"] and check_password_hash(CFG["password_hash"], pwd):
                _login_state["fails"] = 0
                session.clear()
                session["auth"] = True
                return redirect(".")
            time.sleep(1)  # slow down password guessing
            _login_state["fails"] += 1
            if _login_state["fails"] >= 5:
                _login_state["until"] = time.time() + 60
                _login_state["fails"] = 0
                error = "locked"
            else:
                error = "invalid"
    html = (LOGIN_PAGE
            .replace("{{login_css}}", LOGIN_CSS)
            .replace("{{base}}", BASE_CSS)
            .replace("{{bg}}", BG_LAYER)
            .replace("{{i18n}}", I18N_JS)
            .replace("{{error}}", error))
    return Response(html, mimetype="text/html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("login")


@app.route("/")
@login_required
def index():
    html = (PAGE
            .replace("{{page_css}}", PAGE_CSS)
            .replace("{{base}}", BASE_CSS)
            .replace("{{bg}}", BG_LAYER)
            .replace("{{i18n}}", I18N_JS)
            .replace("{{version}}", VERSION))
    return Response(html, mimetype="text/html")


# ---------- Startup ----------

try:
    init_db()
except Exception as e:
    print("db init error:", type(e).__name__, flush=True)

for _fn in (_ping_loop, _location_loop, _services_loop, _processes_loop,
            _collect_loop, _sample_loop, _alert_loop):
    threading.Thread(target=_fn, daemon=True).start()


if __name__ == "__main__":
    app.run(host=CFG.get("host", "127.0.0.1"), port=int(CFG.get("port", 5000)))
