
# ssl_agent_setup_gui.py - One-file GUI that sets Server URL & Token and installs the Windows Service
# Run: python ssl_agent_setup_gui.py
import os, sys, json, subprocess, ctypes
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

CFG_DIR = r"C:\ProgramData\SSLAgent"
CFG_PATH = os.path.join(CFG_DIR, "config.json")
SERVICE_SCRIPT = os.path.join(CFG_DIR, "agent_service.py")
SERVICE_NAME = "SSLAgent"

# Service code to be written to C:\ProgramData\SSLAgent\agent_service.py
SERVICE_PY = r"""# agent_service.py - Windows Service that long-polls WordPress and reports SSL expiry
import win32event, win32serviceutil, win32service, servicemanager
import threading, time, json, os, traceback, socket, ssl, datetime, requests

APP_NAME = "SSLAgent"
APP_DISPLAY = "SSL Expiry Agent"
CFG_DIR = r"C:\ProgramData\SSLAgent"
CFG_PATH = os.path.join(CFG_DIR, "config.json")

def load_cfg():
    if not os.path.exists(CFG_PATH):
        return None
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def get_expiry_ts(host: str, port: int = 443, timeout: int = 8) -> int:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            na = cert.get("notAfter")
            dt = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
            return int(dt.timestamp())

def check_once(site_url: str) -> dict:
    from urllib.parse import urlparse
    u = site_url if "://" in site_url else "https://" + site_url
    p = urlparse(u)
    ts = get_expiry_ts(p.hostname, p.port or 443)
    return {"expiry_ts": ts, "status": "ok"}

def worker(server_base, token, job):
    jid = job.get("id")
    payload = {"id": jid, "post_id": job.get("post_id")}
    try:
        res = check_once(job["site_url"])
        payload.update(res)
    except Exception as e:
        payload.update({"status":"error","error":str(e)})
    try:
        requests.post(f"{server_base.rstrip('/')}/report", headers={"X-Agent-Token": token}, json=payload, timeout=15)
    except Exception:
        servicemanager.LogErrorMsg("report failed: " + traceback.format_exc())

def poll_loop(stop_evt: threading.Event):
    cfg = load_cfg()
    if not cfg:
        time.sleep(5)
        return
    server_base = cfg.get("server_base","").rstrip("/")
    token = cfg.get("token","")
    t_poll = int(cfg.get("poll_timeout",60))
    backoff = int(cfg.get("retry_backoff",5))
    while not stop_evt.is_set():
        try:
            r = requests.get(f"{server_base}/poll", headers={"X-Agent-Token": token}, timeout=t_poll)
            if r.status_code == 200:
                job = r.json()
                if job and job.get("id"):
                    threading.Thread(target=worker, args=(server_base, token, job), daemon=True).start()
            else:
                time.sleep(backoff)
        except Exception:
            time.sleep(backoff)

class Service(win32serviceutil.ServiceFramework):
    _svc_name_ = APP_NAME
    _svc_display_name_ = APP_DISPLAY
    _svc_description_ = "Persistent HTTPS agent that checks SSL expiry for WordPress."
    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop_evt = threading.Event()
    def SvcDoRun(self):
        servicemanager.LogInfoMsg(f"{APP_NAME} starting")
        try:
            poll_loop(self._stop_evt)
        except Exception:
            servicemanager.LogErrorMsg(traceback.format_exc())
    def SvcStop(self):
        self._stop_evt.set()
        win32event.SetEvent(self.hWaitStop)
        servicemanager.LogInfoMsg(f"{APP_NAME} stopping")

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(Service)
"""

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate_if_needed():
    if is_admin():
        return
    params = " ".join(['"'+p+'"' for p in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

def ensure_packages():
    def need(mod):
        try:
            __import__(mod); return False
        except ImportError:
            return True
    pkgs = []
    if need("requests"): pkgs.append("requests")
    if need("win32serviceutil"): pkgs.append("pywin32")
    if pkgs:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade"] + pkgs, shell=False)
        try:
            subprocess.run([sys.executable, "-m", "pywin32_postinstall", "-install"], check=False)
        except Exception:
            pass

def write_files(server, token):
    os.makedirs(CFG_DIR, exist_ok=True)
    cfg = {"server_base": server.rstrip("/"), "token": token, "poll_timeout": 60, "retry_backoff": 5}
    with open(CFG_PATH, "w", encoding="utf-8") as f: json.dump(cfg, f, indent=2)
    with open(SERVICE_SCRIPT, "w", encoding="utf-8") as f: f.write(SERVICE_PY)

def install_service():
    subprocess.check_call([sys.executable, SERVICE_SCRIPT, "--startup", "auto", "install"], shell=False)
    subprocess.check_call([sys.executable, SERVICE_SCRIPT, "start"], shell=False)

def service_running():
    try:
        out = subprocess.check_output(["sc", "query", SERVICE_NAME], stderr=subprocess.STDOUT, text=True)
        return "RUNNING" in out.upper()
    except Exception:
        return False

def on_save(url_entry, token_entry, root):
    server = url_entry.get().strip()
    token  = token_entry.get().strip()
    if not (server.startswith("https://") or server.startswith("http://")):
        messagebox.showerror("Error", "הכנס כתובת שרת מלאה, לדוגמה: https://kbtest.macomp.co.il/wp-json/ssl-agent/v1")
        return
    if not token:
        messagebox.showerror("Error", "חסר Token")
        return
    try:
        elevate_if_needed()
        ensure_packages()
        write_files(server, token)
        install_service()
        ok = service_running()
        if ok:
            messagebox.showinfo("OK", "השירות הותקן ורץ. ההגדרות נשמרו ב- C:\\ProgramData\\SSLAgent\\config.json")
        else:
            messagebox.showwarning("Check", "השירות הותקן אך לא מזוהה כ-RUNNING. בדוק Services.")
        root.destroy()
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Install error", f"שגיאת התקנה: {e}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    root.title("SSL Agent - הגדרה והתקנה")
    root.geometry("460x220")
    root.resizable(False, False)

    tk.Label(root, text="WordPress Server URL (REST Base):").pack(pady=(16,4))
    url_entry = tk.Entry(root, width=60)
    url_entry.insert(0, "https://kbtest.macomp.co.il/wp-json/ssl-agent/v1")
    url_entry.pack()

    tk.Label(root, text="Auth Token:").pack(pady=(10,4))
    token_entry = tk.Entry(root, width=60, show="*")
    token_entry.pack()

    tk.Button(root, text="שמור והתקן שירות", command=lambda: on_save(url_entry, token_entry, root), width=30).pack(pady=18)
    root.mainloop()

if __name__ == "__main__":
    main()
