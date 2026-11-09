#!/usr/bin/env python3
"""ServerPulse management helper, used by the serverpulse control menu. Created by ArshamSmok."""
import ipaddress
import json
import os
import re
import sys

from werkzeug.security import generate_password_hash

CONF = os.environ.get("SERVERPULSE_CONFIG", "/etc/serverpulse/config.json")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
FIELDS = ("allow_ips", "deny_ips", "allowed_hosts")


def load():
    with open(CONF, encoding="utf-8") as f:
        return json.load(f)


def save(conf):
    with open(CONF, "w", encoding="utf-8") as f:
        json.dump(conf, f, ensure_ascii=False, indent=2)
    os.chmod(CONF, 0o600)


def parse_list(text, kind):
    items = [x.strip() for x in text.split(",") if x.strip()]
    for item in items:
        if kind == "ip":
            ipaddress.ip_network(item, strict=False)  # raises ValueError if invalid
        else:
            try:
                ipaddress.ip_address(item)
            except ValueError:
                if not HOST_RE.match(item):
                    raise ValueError(f"not a valid IP or domain: {item}")
    return items


def main():
    cmd = sys.argv[1]
    conf = load()
    if cmd == "set-password":
        pw = os.environ.get("SP_PASS", "")
        if len(pw) < 8:
            raise ValueError("password must be at least 8 characters")
        conf["password_hash"] = generate_password_hash(pw)
    elif cmd == "set-user":
        user = os.environ.get("SP_VAL", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", user):
            raise ValueError("username must be 3-32 characters: letters, digits, _ . -")
        conf["username"] = user
    elif cmd == "set-access":
        field = sys.argv[2]
        if field not in FIELDS:
            raise ValueError("unknown access field")
        kind = "host" if field == "allowed_hosts" else "ip"
        conf[field] = parse_list(os.environ.get("SP_VAL", ""), kind)
    elif cmd == "set-telegram":
        conf.setdefault("alerts", {})
        conf["alerts"]["telegram_token"] = os.environ.get("SP_TOKEN", "").strip()
        conf["alerts"]["chat_id"] = os.environ.get("SP_CHAT", "").strip()
    elif cmd == "show":
        keys = ("username", "port") + FIELDS
        print(json.dumps({k: conf.get(k) for k in keys}))
        return
    else:
        raise ValueError("unknown command")
    save(conf)
    print("ok")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
