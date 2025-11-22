# SSLAgent service
import os
import time
import json
import logging
import socket
import ssl
import datetime
import urllib.parse
from logging.handlers import TimedRotatingFileHandler

try:
    import requests
except Exception:
    requests = None

CFG_DIR = r"C:\ProgramData\SSLAgent"
CFG_PATH = os.path.join(CFG_DIR, "config.json")
LOG_DIR = os.path.join(CFG_DIR, "log")
CABUNDLE_PATH = os.path.join(CFG_DIR, "ca-bundle.pem")


def log_setup():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("SSLAgent")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = TimedRotatingFileHandler(
            os.path.join(LOG_DIR, "agent.log"),
            when="midnight",
            interval=1,
            backupCount=14,
            encoding="utf-8",
        )
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(h)
    return logger


log = log_setup()


def load_cfg():
    """Load config.json with UTF-8/BOM support."""
    with open(CFG_PATH, "r", encoding="utf-8-sig") as f:
        c = json.load(f)
    c["server_base"] = c["server_base"].strip().rstrip("/")
    c["token"] = c["token"].strip()
    return c


def sess():
    """Create a requests session, using local CA bundle if exists."""
    if requests is None:
        return None
    s = requests.Session()
    if os.path.isfile(CABUNDLE_PATH):
        s.verify = CABUNDLE_PATH
    return s


def build_api_url(base: str, action: str) -> str:
    """
    Build full API URL for a given action ("poll", "ack", "report")
    Supports:
      - https://example.com/wp-json/ssl-agent/v1
      - https://example.com/?rest_route=/ssl-agent/v1
    """
    if "rest_route=" in base:
        # example: base = "https://site/?rest_route=/ssl-agent/v1"
        before, after = base.split("rest_route=", 1)
        route = after.rstrip("/") + "/" + action
        return f"{before}rest_route={route}"
    # default wp-json style
    return f"{base}/{action}"


def _parse_target(task: dict):
    """
    Decide which host/port/scheme לבדוק.

    עדיפות:
      1. context.target_host / target_port / scheme
      2. site_url
      3. ברירת מחדל: port=443, scheme=https
    """
    ctx = task.get("context") or {}
    host = ctx.get("target_host")
    port = ctx.get("target_port")
    scheme = ctx.get("scheme") or "https"
    site_url = task.get("site_url") or ctx.get("site_url")

    # אם לא הוגדר host מפורש, גוזרים מתוך URL
    if not host and site_url:
        u = urllib.parse.urlparse(site_url)
        host = u.hostname
        port = u.port
        if not port:
            port = 443 if (u.scheme or "https") == "https" else 80
        scheme = u.scheme or scheme

    if not host:
        raise ValueError("missing host")

    if not port:
        port = 443

    return host, int(port), scheme, site_url


def _fetch_cert(host: str, port: int, timeout: int = 15) -> dict:
    """
    פתיחת TLS ל-host:port והחזרת פרטי התעודה.
    """
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()

    not_after = cert.get("notAfter")  # e.g. 'Dec 31 23:59:59 2029 GMT'

    # CN
    subj = dict(x for x in (cert.get("subject") or [])[0])
    cn = subj.get("commonName") or subj.get("CN") or ""

    # Issuer
    iss = dict(x for x in (cert.get("issuer") or [])[0])
    issuer_name = iss.get("organizationName") or iss.get("O") or ""

    # SANs
    san = []
    for t in cert.get("subjectAltName", []):
        if t and len(t) >= 2:
            san.append(t[1])

    # expiry_ts
    expiry_ts = 0
    if not_after:
        try:
            tm = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_ts = int(tm.replace(tzinfo=datetime.timezone.utc).timestamp())
        except Exception:
            pass

    return {
        "not_after": not_after or "",
        "common_name": cn,
        "issuer_name": issuer_name,
        "subject_alt_names": san,
        "expiry_ts": expiry_ts,
    }


def _report_url(base: str, task: dict) -> str:
    """
    קובע את כתובת ה-report.
    אם השרת החזיר callback במשימה – משתמשים בו.
    אחרת: בונים URL מה-base.
    """
    cb = task.get("callback")
    if cb:
        return cb
    return build_api_url(base, "report")


def once():
    c = load_cfg()
    s = sess()
    if s is None:
        log.warning("requests module missing; skipping")
        return

    hdr = {"X-Agent-Token": c["token"], "Content-Type": "application/json"}

    # PULL TASKS
    poll_url = build_api_url(c["server_base"], "poll")
    try:
        r = s.get(poll_url, headers=hdr, timeout=20)
        if r.status_code != 200:
            log.warning("poll status=%s", r.status_code)
            return
        payload = r.json() if r.content else {}
        if not isinstance(payload, dict):
            log.error("poll error: payload is not a dict: %r", payload)
            return
    except Exception as e:
        log.error("poll error: %s", e)
        return

    tasks = payload.get("tasks") or payload.get("jobs") or []
    if not isinstance(tasks, list):
        log.warning("poll malformed payload, tasks is not a list: %r", tasks)
        return
    if not tasks:
        return

    results = []
    acks = []
    now = datetime.datetime.utcnow

    for t in tasks:
        tid = t.get("id")
        rid = t.get("request_id") or ""
        if not tid:
            continue

        try:
            host, port, scheme, site_url = _parse_target(t)
            if scheme.lower() != "https" and port != 443:
                raise ValueError(f"non-https port={port}")

            cert = _fetch_cert(host, port)
            status = "ok" if cert.get("expiry_ts", 0) > 0 else "error"

            res = {
                "id": tid,
                "request_id": rid,
                "site_url": site_url or "",
                "check_name": "tls_expiry",
                "status": status,
                "error": None if status == "ok" else "missing expiry_ts",
                "latency_ms": None,  # ניתן להוסיף מדידת זמן אם תרצה
                "executed_at": now().isoformat() + "Z",
                "source": "agent",
                "initiator": "poll",
                "target_host": host,
                "target_port": port,
                "scheme": scheme,
                **cert,
            }
            results.append(res)

        except Exception as e:
            res = {
                "id": tid,
                "request_id": rid,
                "site_url": t.get("site_url") or "",
                "check_name": "tls_expiry",
                "status": "error",
                "error": str(e),
                "executed_at": now().isoformat() + "Z",
                "source": "agent",
                "initiator": "poll",
                "target_host": (t.get("context") or {}).get("target_host"),
                "target_port": (t.get("context") or {}).get("target_port"),
                "scheme": (t.get("context") or {}).get("scheme") or "https",
                "expiry_ts": 0,
                "not_after": "",
                "common_name": "",
                "issuer_name": "",
                "subject_alt_names": [],
            }
            results.append(res)

        acks.append({"id": tid, "request_id": rid})

    # ACK
    try:
        ack_url = build_api_url(c["server_base"], "ack")
        s.post(ack_url, headers=hdr, json={"tasks": acks}, timeout=20)
    except Exception as e:
        log.error("ack error: %s", e)

    # REPORT
    try:
        report_url = _report_url(c["server_base"], tasks[0])
        rr = s.post(report_url, headers=hdr, json={"results": results}, timeout=30)
        if rr.status_code != 200:
            log.warning("report status=%s body=%s", rr.status_code, rr.text[:500])
    except Exception as e:
        log.error("report error: %s", e)


def main():
    log.info("SSLAgent service starting")
    while True:
        try:
            once()
        except Exception as e:
            log.error("loop error: %s", e)
        time.sleep(60)


if __name__ == "__main__":
    main()
