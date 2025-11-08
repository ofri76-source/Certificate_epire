# SSLAgent service (no pywin32)
import os, time, json, logging
from logging.handlers import TimedRotatingFileHandler

try:
    import requests
except Exception:
    requests = None

CFG_DIR=r"C:\\ProgramData\\SSLAgent"
CFG_PATH=os.path.join(CFG_DIR,"config.json")
LOG_DIR=os.path.join(CFG_DIR,"log")
CABUNDLE_PATH=os.path.join(CFG_DIR,"ca-bundle.pem")


def log_setup():
    os.makedirs(LOG_DIR, exist_ok=True)
    L=logging.getLogger("SSLAgent"); L.setLevel(logging.INFO)
    if not L.handlers:
        h=TimedRotatingFileHandler(os.path.join(LOG_DIR,"agent.log"), when="midnight", interval=1, backupCount=14, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        L.addHandler(h)
    return L

log=log_setup()


def load_cfg():
    with open(CFG_PATH,"r",encoding="utf-8-sig") as f:
        c=json.load(f)
    c["server_base"]=c["server_base"].strip().rstrip("/")
    c["token"]=c["token"].strip()
    return c


def sess():
    if requests is None:
        return None
    s=requests.Session()
    if os.path.isfile(CABUNDLE_PATH):
        s.verify=CABUNDLE_PATH
    return s


def once():
    c=load_cfg(); s=sess()
    if s is None:
        log.warning("requests module missing; skipping poll")
        return
    hdr={"X-Agent-Token": c["token"], "Content-Type":"application/json"}
    try:
        r=s.get(f"{c['server_base']}/poll", headers=hdr, timeout=20)
        if r.status_code==200:
            jobs=r.json().get("jobs", [])
            for j in jobs:
                # Placeholder for real work
                log.info("job: %s", j)
                s.post(f"{c['server_base']}/ack", headers=hdr, json={"id": j.get("id")}, timeout=20)
        else:
            log.warning("poll status=%s", r.status_code)
    except Exception as e:
        log.error("poll error: %s", e)


def main():
    log.info("SSLAgent service starting")
    while True:
        try:
            once()
        except Exception as e:
            log.error("loop error: %s", e)
        time.sleep(60)


if __name__=="__main__":
    main()
