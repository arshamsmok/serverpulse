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

VERSION = "1.3.0"
HOST = socket.gethostname()

# تنظیمات از فایلی خوانده می‌شود که install.sh می‌سازد
CONFIG_PATH = os.environ.get("SERVERPULSE_CONFIG", "/etc/serverpulse/config.json")
with open(CONFIG_PATH, encoding="utf-8") as _f:
    CFG = json.load(_f)

app.secret_key = CFG["secret_key"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DB_PATH = CFG.get("db_path", "/var/lib/serverpulse/history.db")
SAMPLE_INTERVAL = max(1, int(CFG.get("sample_interval", 60)))
ALERTS = CFG.get("alerts", {})
SERVICES = [s for s in CFG.get("services", []) if re.fullmatch(r"[A-Za-z0-9@._-]+", s)]

# هدف‌های پینگ. lat/lng فقط برای نقشه است.
# برای IPهای anycast مثل 1.1.1.1 مختصات نمی‌گذاریم چون به نزدیک‌ترین مرکز داده می‌رسند.
TARGETS = [
    {"ip": "8.8.8.8",      "name": "Google DNS", "country": "آمریکا",    "code": "US",     "lat": 37.42,  "lng": -122.08},
    {"ip": "9.9.9.9",      "name": "Quad9",      "country": "سوئیس",     "code": "CH",     "lat": 47.37,  "lng": 8.54},
    {"ip": "77.88.8.8",    "name": "Yandex DNS", "country": "روسیه",     "code": "RU",     "lat": 55.75,  "lng": 37.62},
    {"ip": "223.5.5.5",    "name": "AliDNS",     "country": "چین",       "code": "CN",     "lat": 30.29,  "lng": 120.16},
    {"ip": "168.126.63.1", "name": "KT DNS",     "country": "کره جنوبی", "code": "KR",     "lat": 37.57,  "lng": 126.98},
    {"ip": "1.1.1.1",      "name": "Cloudflare", "country": "جهانی",     "code": "GLOBAL", "lat": None,   "lng": None},
]

PING_INTERVAL = 30  # ثانیه بین هر دور پینگ
PING_COUNT = 5      # تعداد بسته در هر دور، برای محاسبه جیتر و افت بسته
# بازه تاریخچه: (طول بازه بر حسب ثانیه، اندازه هر نقطه بر حسب ثانیه)
RANGES = {"1h": (3600, 60), "24h": (86400, 900), "7d": (7 * 86400, 3600)}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect("login")
        return fn(*args, **kwargs)
    return wrapper


_lock = threading.Lock()        # برای پینگ، موقعیت و سرویس‌ها
_snap_lock = threading.Lock()   # برای اسنپ‌شات زنده
_ping = {t["ip"]: {"avg": None, "jitter": None, "loss": 100.0} for t in TARGETS}
_server = {"value": None}
_services = {"value": []}
_snap = {"value": {}}
_net = {"last": psutil.net_io_counters(), "time": time.time()}
_alert_state = {}

RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
LOSS_RE = re.compile(r"([\d.]+)% packet loss")


def ping_host(host):
    """پینگ چند بسته‌ای: میانگین، جیتر (mdev) و درصد افت بسته را برمی‌گرداند."""
    try:
        out = subprocess.run(
            ["ping", "-c", str(PING_COUNT), "-W", "2", host],
            capture_output=True, text=True, timeout=20
        ).stdout
    except Exception:
        return {"avg": None, "jitter": None, "loss": 100.0}
    loss_m = LOSS_RE.search(out)
    loss = float(loss_m.group(1)) if loss_m else 100.0
    rtt = RTT_RE.search(out)
    if not rtt:
        return {"avg": None, "jitter": None, "loss": loss}
    return {"avg": round(float(rtt.group(2)), 1),
            "jitter": round(float(rtt.group(4)), 1),
            "loss": loss}


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
                        "ip": d.get("query"),
                        "country": d.get("country"),
                        "countryCode": d.get("countryCode"),
                        "city": d.get("city"),
                        "isp": d.get("isp"),
                        "lat": d.get("lat"),
                        "lon": d.get("lon"),
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


def _collect_loop():
    """یک بار در ثانیه آمار را جمع می‌کند. همه کلاینت‌ها از همین اسنپ‌شات می‌خوانند."""
    psutil.cpu_percent(interval=None)  # نقطه شروع اندازه‌گیری CPU
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
            "targets": [{**t, **pings[t["ip"]]} for t in TARGETS],
        }
        with _snap_lock:
            _snap["value"] = snap
        time.sleep(2)


# ---------- تاریخچه (SQLite) ----------

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


# ---------- هشدار تلگرام ----------

def send_telegram(text):
    token = ALERTS.get("telegram_token")
    chat = ALERTS.get("chat_id")
    if not token or not chat:
        return False
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage",
                               data=data, timeout=10)
        return True
    except Exception as e:
        print("telegram error:", type(e).__name__, flush=True)
        return False


def describe(key, value, thr, down):
    if key.startswith("down:"):
        name = key[5:]
        if down:
            return f"[{HOST}] 🔴 پینگ به {name} قطع است"
        return f"[{HOST}] 🟢 پینگ به {name} برگشت"
    label = {"cpu": "CPU", "ram": "RAM", "disk": "Disk"}[key]
    if down:
        return f"[{HOST}] ⚠️ {label} به {value:.1f}% رسید (حد {thr}%)"
    return f"[{HOST}] ✅ {label} به حالت عادی برگشت ({value:.1f}%)"


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


# ---------- مسیرها ----------

@app.route("/api/stats")
@login_required
def stats():
    with _snap_lock:
        snap = _snap["value"]
    if not snap:
        return jsonify({"error": "warming up"}), 503
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


BASE_CSS = r"""
  :root{--text:#e2e8f0;--muted:#94a3b8;--c1:#38bdf8;--c2:#a78bfa}
  *{box-sizing:border-box}
  html{min-height:100%;background:radial-gradient(ellipse at 15% 0%,rgba(14,165,233,.22),transparent 55%),radial-gradient(ellipse at 90% 100%,rgba(34,197,94,.14),transparent 50%),linear-gradient(180deg,#060b16 0%,#0b1220 100%);background-attachment:fixed}
  body{margin:0;min-height:100vh;font-family:Vazirmatn,Tahoma,sans-serif;color:var(--text);background:none}
  body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;opacity:1;
    background-image:url("data:image/svg+xml;utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='260' height='130'%3E%3Cg fill='none' stroke='%2394a3b8' stroke-opacity='0.34'%3E%3Crect x='10' y='10' width='150' height='26' rx='4'/%3E%3Crect x='10' y='44' width='150' height='26' rx='4'/%3E%3Crect x='10' y='78' width='150' height='26' rx='4'/%3E%3C/g%3E%3Ccircle cx='140' cy='23' r='2.5' fill='%2322c55e'/%3E%3Ccircle cx='150' cy='23' r='2' fill='%2338bdf8'/%3E%3Ccircle cx='140' cy='57' r='2.5' fill='%2322c55e'/%3E%3Ccircle cx='150' cy='57' r='2' fill='%23f59e0b'/%3E%3Ccircle cx='140' cy='91' r='2.5' fill='%2338bdf8'/%3E%3C/svg%3E");
    background-size:260px 130px}
  body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
    background-image:linear-gradient(rgba(56,189,248,.11) 1px,transparent 1px),linear-gradient(90deg,rgba(56,189,248,.11) 1px,transparent 1px);
    background-size:48px 48px;
    -webkit-mask-image:linear-gradient(180deg,#000 30%,transparent 95%);mask-image:linear-gradient(180deg,#000 30%,transparent 95%)}
  .card,.chart-box,.box{position:relative;min-width:0;padding:16px 18px;border-radius:20px;
    background:linear-gradient(135deg,rgba(255,255,255,.16),rgba(255,255,255,.05));
    -webkit-backdrop-filter:blur(16px) saturate(140%);backdrop-filter:blur(16px) saturate(140%);
    box-shadow:0 12px 32px rgba(0,0,0,.35),inset 0 1px 0 rgba(255,255,255,.14);
    transition:transform .3s ease,box-shadow .3s ease}
  .card:hover,.chart-box:hover,.box:hover{transform:scale(1.025);
    box-shadow:0 18px 44px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.22)}
"""


LOGIN_PAGE = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ورود · ServerPulse</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vazirmatn@33.0.3/Vazirmatn-font-face.css">
<style>{{base}}
  body{display:flex;align-items:center;justify-content:center}
  .box{width:min(360px,92vw);padding:30px}
  h1{margin:0 0 18px;font-size:22px;font-weight:800;text-align:center;color:transparent;
    background:linear-gradient(90deg,#38bdf8,#a78bfa,#f472b6,#fbbf24,#38bdf8);background-size:300% 100%;
    -webkit-background-clip:text;background-clip:text;animation:shift 8s linear infinite}
  @keyframes shift{to{background-position:300% 0}}
  label{display:block;font-size:13px;color:var(--muted);margin:12px 0 6px}
  input{width:100%;padding:11px 14px;border:0;border-radius:12px;font:inherit;direction:ltr;color:#f8fafc;
    background:rgba(255,255,255,.1);box-shadow:inset 0 1px 0 rgba(255,255,255,.1);transition:background .2s,box-shadow .2s}
  input:focus{outline:none;background:rgba(255,255,255,.16);box-shadow:0 0 0 2px rgba(56,189,248,.45)}
  button{margin-top:20px;width:100%;padding:12px;border:0;border-radius:12px;color:#fff;font:inherit;font-weight:600;
    cursor:pointer;background:rgba(255,255,255,.14);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);
    transition:transform .2s,background .2s}
  button:hover{transform:scale(1.03);background:rgba(34,197,94,.35)}
  .err{color:#fca5a5;font-size:13px;margin-top:12px;text-align:center;min-height:18px}
  @media (prefers-reduced-motion: reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<form class="box" method="post" action="login" style="--c1:#16a34a;--c2:#db2777">
  <h1>⚡ ServerPulse</h1>
  <label for="u">نام کاربری</label>
  <input id="u" name="username" autocomplete="username" required autofocus>
  <label for="p">رمز عبور</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">ورود</button>
  <div class="err">{{error}}</div>
</form>
</body>
</html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        if user == CFG["username"] and check_password_hash(CFG["password_hash"], pwd):
            session.clear()
            session["auth"] = True
            return redirect(".")
        time.sleep(1)  # کند کردن حدس زدن رمز
        error = "نام کاربری یا رمز عبور اشتباه است"
    return Response(LOGIN_PAGE.replace("{{base}}", BASE_CSS).replace("{{error}}", error), mimetype="text/html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("login")


PAGE = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ServerPulse</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vazirmatn@33.0.3/Vazirmatn-font-face.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>{{base}}
  header{display:flex;justify-content:space-between;align-items:center;padding:18px 28px;flex-wrap:wrap;gap:8px}
  header h1{margin:0;font-size:22px;font-weight:800;color:transparent;
    background:linear-gradient(90deg,#38bdf8,#a78bfa,#f472b6,#fbbf24,#38bdf8);background-size:300% 100%;
    -webkit-background-clip:text;background-clip:text;animation:shift 8s linear infinite}
  @keyframes shift{to{background-position:300% 0}}
  #status{font-size:13px;color:var(--muted)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-left:6px}
  .logout{font-size:13px;color:#e2e8f0;text-decoration:none;padding:6px 14px;border-radius:999px;display:inline-block;
    background:rgba(255,255,255,.12);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);
    transition:transform .2s,background .2s}
  .logout:hover{transform:scale(1.06);background:rgba(255,255,255,.24)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;padding:0 28px}
  .wide{grid-column:1/-1}
  .label{font-size:13px;color:var(--muted)}
  .value{font-size:24px;font-weight:700;margin-top:8px;direction:ltr;text-align:right;color:transparent;
    background:linear-gradient(90deg,var(--c1),var(--c2));-webkit-background-clip:text;background-clip:text}
  .value-sm{font-size:17px;font-weight:600;margin-top:8px;color:#f1f5f9}
  .sub{font-size:12px;color:var(--muted);margin-top:4px;direction:ltr;text-align:right}
  .bar{height:6px;background:rgba(255,255,255,.12);border-radius:99px;margin-top:10px;overflow:hidden}
  .bar i{display:block;height:100%;width:0;border-radius:99px;transition:width .6s ease;
    background:linear-gradient(90deg,var(--c1),var(--c2))}
  .chip{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;margin:4px 4px 0 0;border-radius:999px;
    background:rgba(255,255,255,.12);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);
    font-size:13px;color:#e2e8f0;transition:transform .2s}
  .chip:hover{transform:scale(1.05)}
  .toolbar{display:flex;justify-content:space-between;align-items:center;padding:20px 28px 0}
  .seg{display:inline-flex;padding:4px;border-radius:14px;background:rgba(255,255,255,.08);
    -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px)}
  .seg button{border:0;background:transparent;padding:6px 14px;border-radius:10px;font:inherit;font-size:13px;
    color:var(--muted);cursor:pointer;transition:transform .2s,background .2s,color .2s}
  .seg button:hover{transform:scale(1.06);color:#fff}
  .seg button.on{background:rgba(255,255,255,.2);color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.2)}
  .charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;padding:14px 28px 0}
  .chart-box h3{margin:0 0 8px;font-size:14px;font-weight:600;color:var(--c1)}
  #map{height:320px;border-radius:14px;overflow:hidden}
  .leaflet-container{background:#0b1220}
  .leaflet-tile{filter:grayscale(.6) brightness(.7) contrast(1.05)}
  .table-wrap{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 6px;text-align:right;border-bottom:1px solid rgba(255,255,255,.08);white-space:nowrap;color:#e2e8f0}
  th{color:var(--muted);font-weight:600;font-size:12px}
  .ltr{direction:ltr}
  .pd{display:inline-block;width:9px;height:9px;border-radius:50%;margin-left:6px;vertical-align:middle}
  footer{text-align:center;font-size:12px;color:var(--muted);padding:22px}
  @media (prefers-reduced-motion: reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<header>
  <h1>⚡ ServerPulse</h1>
  <div style="display:flex;align-items:center;gap:14px">
    <div id="status"><span class="dot"></span>در حال اتصال</div>
    <a href="logout" class="logout">خروج</a>
  </div>
</header>

<div class="grid">
  <div class="card" style="--c1:#16a34a;--c2:#22d3ee;--dur:5s">
    <div class="label">🧠 پردازنده (CPU)</div>
    <div class="value" id="cpu">-</div>
    <div class="bar"><i id="cpuBar"></i></div>
  </div>
  <div class="card" style="--c1:#db2777;--c2:#a855f7;--dur:7s">
    <div class="label">💾 حافظه (RAM)</div>
    <div class="value" id="ram">-</div>
    <div class="bar"><i id="ramBar"></i></div>
  </div>
  <div class="card" style="--c1:#d97706;--c2:#f43f5e;--dur:6s">
    <div class="label">💽 دیسک</div>
    <div class="value" id="disk">-</div>
    <div class="bar"><i id="diskBar"></i></div>
  </div>
  <div class="card" style="--c1:#0891b2;--c2:#2563eb;--dur:8s">
    <div class="label">📡 میانگین پینگ</div>
    <div class="value" id="avgPing">-</div>
  </div>
  <div class="card" style="--c1:#2563eb;--c2:#06b6d4;--dur:4s">
    <div class="label">⬇️ دریافت</div>
    <div class="value" id="rx">-</div>
  </div>
  <div class="card" style="--c1:#f59e0b;--c2:#ef4444;--dur:4.5s">
    <div class="label">⬆️ ارسال</div>
    <div class="value" id="tx">-</div>
  </div>
  <div class="card" style="--c1:#7c3aed;--c2:#ec4899;--dur:9s">
    <div class="label">⏱ آپتایم</div>
    <div class="value" id="uptime" style="font-size:17px">-</div>
    <div class="sub" id="load">بار: -</div>
  </div>
  <div class="card wide" style="--c1:#16a34a;--c2:#2563eb;--dur:10s">
    <div class="label">📍 موقعیت سرور</div>
    <div class="value-sm" id="loc">در حال دریافت...</div>
    <div class="sub" id="isp"></div>
  </div>
  <div class="card wide" style="--c1:#0891b2;--c2:#16a34a;--dur:12s">
    <div class="label">🛠 سرویس‌ها</div>
    <div id="services" style="margin-top:6px"></div>
  </div>
</div>

<div class="charts">
  <div class="chart-box" style="--c1:#16a34a;--c2:#db2777;--dur:9s">
    <h3>CPU و RAM (زنده)</h3><canvas id="cpuChart"></canvas>
  </div>
  <div class="chart-box" style="--c1:#2563eb;--c2:#d97706;--dur:7s">
    <h3>ترافیک شبکه (زنده، KB/s)</h3><canvas id="netChart"></canvas>
  </div>
  <div class="chart-box wide" style="--c1:#7c3aed;--c2:#0891b2;--dur:11s">
    <h3>پینگ به کشورها (زنده، ms)</h3><canvas id="pingChart"></canvas>
  </div>
</div>

<div class="toolbar">
  <span class="label">📈 تاریخچه</span>
  <div class="seg">
    <button data-r="1h" class="on">۱ ساعت</button>
    <button data-r="24h">۲۴ ساعت</button>
    <button data-r="7d">۷ روز</button>
  </div>
</div>
<div class="charts">
  <div class="chart-box" style="--c1:#16a34a;--c2:#db2777;--dur:9s">
    <h3>تاریخچه CPU و RAM (%)</h3><canvas id="histCpu"></canvas>
  </div>
  <div class="chart-box" style="--c1:#2563eb;--c2:#d97706;--dur:7s">
    <h3>تاریخچه ترافیک (KB/s)</h3><canvas id="histNet"></canvas>
  </div>
</div>

<div class="charts">
  <div class="chart-box" style="--c1:#16a34a;--c2:#0891b2;--dur:8s">
    <h3>نقشه پینگ</h3><div id="map"></div>
  </div>
  <div class="chart-box" style="--c1:#db2777;--c2:#d97706;--dur:6s">
    <h3>جدول پینگ</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>کشور</th><th>سرویس</th><th>IP</th><th>پینگ</th><th>جیتر</th><th>افت بسته</th></tr></thead>
        <tbody id="pingBody"></tbody>
      </table>
    </div>
  </div>
</div>

<footer>ServerPulse v{{version}} · by ArshamSmok · به‌روزرسانی هر ۲ ثانیه</footer>

<script>
const N = 60;
const labels = Array(N).fill("");
const PALETTE = ["#2563eb", "#7c3aed", "#db2777", "#d97706", "#16a34a", "#0891b2"];
const $ = id => document.getElementById(id);

const flag = code => (!code || code === "GLOBAL") ? "🌐" :
  String.fromCodePoint(...[...code.toUpperCase()].map(c => 127397 + c.charCodeAt(0)));
const pingColor = ms => ms === null ? "#9ca3af" : ms < 80 ? "#16a34a" : ms < 200 ? "#d97706" : "#dc2626";
const pingText = ms => ms === null ? "timeout" : ms + " ms";
const STATE_COLOR = { active: "#16a34a", inactive: "#9ca3af", failed: "#dc2626", activating: "#d97706" };

const baseOpts = () => ({
  animation: false, responsive: true,
  scales: {
    x: { display: false },
    y: { beginAtZero: true, grid: { color: "rgba(255,255,255,.08)" }, ticks: { color: "#94a3b8" } }
  },
  plugins: { legend: { labels: { color: "#cbd5e1", font: { family: "Vazirmatn" } } } }
});
const ds = (label, color) => ({
  label, data: Array(N).fill(null), borderColor: color, backgroundColor: color + "26",
  fill: true, tension: .4, pointRadius: 0, borderWidth: 2, spanGaps: false
});
const hds = (label, color) => ({
  label, data: [], borderColor: color, backgroundColor: color + "26",
  fill: true, tension: .35, pointRadius: 0, borderWidth: 2, spanGaps: true
});

const cpuChart = new Chart($("cpuChart"), {
  type: "line", data: { labels, datasets: [ds("CPU %", "#16a34a"), ds("RAM %", "#db2777")] }, options: baseOpts()
});
const netChart = new Chart($("netChart"), {
  type: "line", data: { labels, datasets: [ds("دریافت", "#2563eb"), ds("ارسال", "#d97706")] }, options: baseOpts()
});
let pingChart = null;
function ensurePingChart(targets) {
  if (pingChart) return;
  pingChart = new Chart($("pingChart"), {
    type: "line",
    data: {
      labels,
      datasets: targets.map((t, i) => ({
        label: flag(t.code) + " " + t.country, data: Array(N).fill(null),
        borderColor: PALETTE[i % PALETTE.length], backgroundColor: "transparent",
        tension: .3, pointRadius: 0, borderWidth: 2, spanGaps: false
      }))
    },
    options: baseOpts()
  });
}

const histCpu = new Chart($("histCpu"), {
  type: "line", data: { labels: [], datasets: [hds("CPU %", "#16a34a"), hds("RAM %", "#db2777")] }, options: baseOpts()
});
const histNet = new Chart($("histNet"), {
  type: "line", data: { labels: [], datasets: [hds("دریافت", "#2563eb"), hds("ارسال", "#d97706")] }, options: baseOpts()
});

let histRange = "1h";
function fmtLabel(ts, range) {
  const d = new Date(ts * 1000);
  return range === "7d"
    ? d.toLocaleString("fa-IR", { month: "numeric", day: "numeric", hour: "2-digit" })
    : d.toLocaleTimeString("fa-IR", { hour: "2-digit", minute: "2-digit" });
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
  } catch (e) { /* در صورت خطا، نمودار قبلی می‌ماند */ }
}
document.querySelectorAll(".seg button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".seg button").forEach(x => x.classList.remove("on"));
  b.classList.add("on");
  histRange = b.dataset.r;
  loadHistory();
}));

const map = L.map("map").setView([20, 0], 2);
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 6, attribution: "© OpenStreetMap"
}).addTo(map);
const mapLayer = L.layerGroup().addTo(map);
let fitted = false;

function renderMap(sv, targets) {
  mapLayer.clearLayers();
  const pts = [];
  const hasServer = !!(sv && sv.lat != null);
  if (hasServer) {
    pts.push([sv.lat, sv.lon]);
    L.circleMarker([sv.lat, sv.lon], { radius: 9, color: "#fff", weight: 2, fillColor: "#16a34a", fillOpacity: 1 })
      .bindTooltip("سرور: " + sv.city + "، " + sv.country).addTo(mapLayer);
  }
  targets.forEach(t => {
    if (t.lat == null) return;
    const c = pingColor(t.avg);
    pts.push([t.lat, t.lng]);
    if (hasServer) {
      L.polyline([[sv.lat, sv.lon], [t.lat, t.lng]], { color: c, weight: 2, opacity: .6, dashArray: "6 6" }).addTo(mapLayer);
    }
    L.circleMarker([t.lat, t.lng], { radius: 7, color: "#fff", weight: 2, fillColor: c, fillOpacity: 1 })
      .bindTooltip(flag(t.code) + " " + t.country + ": " + pingText(t.avg)).addTo(mapLayer);
  });
  if (!fitted && pts.length > 1) {
    map.fitBounds(pts, { padding: [30, 30], maxZoom: 4 });
    fitted = true;
  }
}

function renderTable(targets) {
  $("pingBody").innerHTML = targets.map(t =>
    `<tr><td>${flag(t.code)} ${t.country}</td><td>${t.name}</td>` +
    `<td class="ltr">${t.ip}</td>` +
    `<td class="ltr"><span class="pd" style="background:${pingColor(t.avg)}"></span>${pingText(t.avg)}</td>` +
    `<td class="ltr">${t.jitter === null ? "-" : t.jitter + " ms"}</td>` +
    `<td class="ltr">${t.loss === null ? "-" : t.loss.toFixed(1) + "%"}</td></tr>`
  ).join("");
}

function renderServices(list) {
  $("services").innerHTML = list.length
    ? list.map(s => `<span class="chip"><span class="pd" style="margin:0;background:${STATE_COLOR[s.state] || "#9ca3af"}"></span>${s.name} · ${s.state}</span>`).join("")
    : '<span class="sub">سرویسی در تنظیمات نیست</span>';
}

function renderLoc(sv) {
  if (!sv) {
    $("loc").textContent = "نامشخص";
    $("isp").textContent = "اطلاعات موقعیت در دسترس نیست (اینترنت یا ip-api)";
    return;
  }
  $("loc").textContent = flag(sv.countryCode) + " " + sv.city + "، " + sv.country;
  $("isp").textContent = "IP: " + sv.ip + "  ·  " + sv.isp;
}

const fmtRate = b => {
  const u = ["B/s", "KB/s", "MB/s", "GB/s"]; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(1) + " " + u[i];
};
const fmtUptime = s =>
  `${Math.floor(s / 86400)} روز ${Math.floor(s % 86400 / 3600)} ساعت ${Math.floor(s % 3600 / 60)} دقیقه`;
const setBar = (id, pct) => $(id).style.width = Math.min(pct, 100) + "%";
const push = (chart, vals) => {
  chart.data.datasets.forEach((d, i) => { d.data.push(vals[i]); d.data.shift(); });
  chart.update("none");
};
function setStatus(online) {
  $("status").innerHTML = online
    ? '<span class="dot"></span>آنلاین'
    : '<span class="dot" style="background:#dc2626"></span>قطع اتصال';
}

let inFlight = false;
let lastSig = "";
let lastSvc = "";

async function tick() {
  // در تب پنهان یا وقتی درخواست قبلی هنوز جواب نیامده، درخواست جدید نفرست
  if (document.hidden || inFlight) return;
  inFlight = true;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch("api/stats", { cache: "no-store", signal: ctrl.signal });
    if (r.status === 401) { location.href = "login"; return; }
    if (r.status === 503) return; // سرور هنوز داده آماده ندارد
    const s = await r.json();

    $("cpu").textContent = s.cpu.toFixed(1) + "%";
    $("ram").textContent = s.ram.toFixed(1) + "%";
    $("disk").textContent = s.disk.toFixed(1) + "%";
    setBar("cpuBar", s.cpu); setBar("ramBar", s.ram); setBar("diskBar", s.disk);
    $("rx").textContent = fmtRate(s.rx);
    $("tx").textContent = fmtRate(s.tx);
    $("uptime").textContent = fmtUptime(s.uptime);
    $("load").textContent = "بار: " + s.load.join(" · ");
    $("avgPing").textContent = s.ping_avg === null ? "timeout" : s.ping_avg.toFixed(1) + " ms";

    const svcSig = JSON.stringify(s.services);
    if (svcSig !== lastSvc) { renderServices(s.services); lastSvc = svcSig; }

    renderLoc(s.server);
    ensurePingChart(s.targets);
    push(cpuChart, [s.cpu, s.ram]);
    push(netChart, [s.rx / 1024, s.tx / 1024]);
    push(pingChart, s.targets.map(t => t.avg));

    // جدول و نقشه فقط وقتی داده پینگ یا موقعیت تغییر کرده باشد بازسازی می‌شوند
    const sig = JSON.stringify([s.targets.map(t => [t.avg, t.jitter, t.loss]), s.server]);
    if (sig !== lastSig) {
      renderTable(s.targets);
      renderMap(s.server, s.targets);
      lastSig = sig;
    }
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
setInterval(tick, 2000);
setInterval(loadHistory, 60000);
tick();
loadHistory();
</script>
</body>
</html>"""


@app.route("/")
@login_required
def index():
    return Response(PAGE.replace("{{base}}", BASE_CSS).replace("{{version}}", VERSION), mimetype="text/html")


# ---------- راه‌اندازی ----------

try:
    init_db()
except Exception as e:
    print("db init error:", type(e).__name__, flush=True)

for _fn in (_ping_loop, _location_loop, _services_loop, _collect_loop, _sample_loop, _alert_loop):
    threading.Thread(target=_fn, daemon=True).start()


if __name__ == "__main__":
    app.run(host=CFG.get("host", "127.0.0.1"), port=int(CFG.get("port", 5000)))
