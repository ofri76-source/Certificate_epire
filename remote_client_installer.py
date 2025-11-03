#!/usr/bin/env python3
"""Installer for the SSL remote HTTPS client service.

This script configures a persistent systemd service that exposes an HTTPS
listener on the office workstation. WordPress dispatches certificate checks
through this endpoint and receives reports once each check completes.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict
import logging

SERVICE_SCRIPT = """#!/usr/bin/env python3
import argparse
import json
import logging
import logging.handlers
import os
import queue
import signal
import socket
import ssl
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
import hmac

class RemoteRequestHandler(BaseHTTPRequestHandler):
    server_version = "SSLRemoteClient/1.0"

    def do_GET(self):
        if self.path.split('?', 1)[0] == '/health':
            payload = json.dumps({
                'status': 'ok',
                'timestamp': int(time.time()),
                'queued': self.server.queue.qsize(),
            }).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404, 'Not Found')

    def do_POST(self):
        if self.path != '/api/check':
            self.send_error(404, 'Not Found')
            return
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            self.send_response(401)
            self.end_headers()
            return
        token = auth.split(' ', 1)[1].strip()
        if not hmac.compare_digest(token, self.server.auth_token):
            self.send_response(403)
            self.end_headers()
            return
        try:
            length = int(self.headers.get('Content-Length') or '0')
        except ValueError:
            length = 0
        if length <= 0:
            self.send_error(400, 'Missing payload')
            return
        try:
            data = json.loads(self.rfile.read(length).decode('utf-8'))
        except Exception as exc:  # pragma: no cover - defensive
            self.server.logger.warning('Invalid payload: %s', exc)
            self.send_error(400, 'Invalid JSON payload')
            return
        job = self._normalize_job(data)
        if not job:
            self.send_error(400, 'Missing required fields')
            return
        try:
            self.server.queue.put_nowait(job)
        except queue.Full:
            self.send_error(429, 'Queue full')
            return
        payload = json.dumps({'queued': True, 'request_id': job['request_id']}).encode('utf-8')
        self.send_response(202)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):  # pragma: no cover - silence default logger
        self.server.logger.debug("http: " + fmt, *args)

    def _normalize_job(self, data: Dict[str, Any]):
        site_url = (data.get('site_url') or '').strip()
        callback = (data.get('callback') or '').strip()
        token = (data.get('token') or '').strip()
        request_id = (data.get('request_id') or '') or f"req-{int(time.time()*1000)}"
        if not site_url or not callback:
            return None
        try:
            job_id = int(data.get('id'))
        except (ValueError, TypeError):
            return None
        return {
            'id': job_id,
            'site_url': site_url,
            'callback': callback,
            'token': token,
            'context': data.get('context') or 'unknown',
            'request_id': request_id,
            'report_timeout': int(data.get('report_timeout') or self.server.report_timeout),
        }


def create_ssl_context(config: Dict[str, Any]):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config['tls_cert'], config['tls_key'])
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES256')
    return context


def fetch_expiry_timestamp(url: str, timeout: int) -> int:
    if '://' not in url:
        url = 'https://' + url
    parsed = urllib_parse.urlparse(url)
    if parsed.scheme.lower() != 'https':
        raise ValueError('Only HTTPS URLs are supported')
    host = parsed.hostname
    if not host:
        raise ValueError('Invalid URL host')
    port = parsed.port or 443
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    if not cert or 'notAfter' not in cert:
        raise RuntimeError('Certificate data not available')
    expires = cert['notAfter']
    expiry_dt = datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')
    return int(expiry_dt.timestamp())


def send_report(result: Dict[str, Any], job: Dict[str, Any], server) -> bool:
    payload = json.dumps({'results': [result]}).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'ssl-remote-client/1.0',
    }
    if job['token']:
        headers['X-SSL-Token'] = job['token']
    request = urllib_request.Request(job['callback'], data=payload, headers=headers, method='POST')
    if job['callback'].startswith('https://'):
        if server.verify_callback:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()
    else:
        context = None
    try:
        with urllib_request.urlopen(request, timeout=job['report_timeout'], context=context) as resp:
            resp.read()
        return True
    except urllib_error.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='ignore') if hasattr(exc, 'read') else ''
        server.logger.error('Report HTTP error %s: %s', exc.code, body)
    except Exception as exc:  # pragma: no cover - network failures
        server.logger.error('Report error: %s', exc)
    return False


class Worker(threading.Thread):
    daemon = True

    def __init__(self, server):
        super().__init__(daemon=True)
        self.server = server

    def run(self):
        q = self.server.queue
        while not self.server.shutdown_flag.is_set():
            try:
                job = q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self.handle_job(job)
            finally:
                q.task_done()

    def handle_job(self, job: Dict[str, Any]):
        logger = self.server.logger
        logger.info('Processing #%s (%s)', job['id'], job['context'])
        result = {'id': job['id']}
        try:
            expiry_ts = fetch_expiry_timestamp(job['site_url'], self.server.connect_timeout)
            result['expiry_ts'] = expiry_ts
        except Exception as exc:
            logger.error('Fetch failed for %s: %s', job['site_url'], exc)
            result['error'] = str(exc)
        success = send_report(result, job, self.server)
        if success:
            logger.info('Reported #%s successfully', job['id'])
        else:
            logger.error('Failed to report result for #%s', job['id'])


def load_config(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger('ssl-remote-client')
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
    handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger


def main():
    parser = argparse.ArgumentParser(description='SSL remote client service runner')
    parser.add_argument('--config', required=True, help='Path to the generated config file')
    args = parser.parse_args()
    config = load_config(args.config)
    logger = setup_logger(config['log_path'])
    server = ThreadingHTTPServer((config['listen_host'], int(config['listen_port'])), RemoteRequestHandler)
    server.queue = queue.Queue(maxsize=5000)
    server.logger = logger
    server.auth_token = config['auth_token']
    server.verify_callback = bool(config.get('verify_callback', True))
    server.connect_timeout = int(config.get('connect_timeout', 15))
    server.report_timeout = int(config.get('report_timeout', 20))
    server.shutdown_flag = threading.Event()
    context = create_ssl_context(config)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    workers = []
    for _ in range(max(1, int(config.get('workers', 4)))):
        worker = Worker(server)
        worker.start()
        workers.append(worker)

    def handle_signal(signum, frame):  # pragma: no cover - runtime
        logger.info('Stopping service (signal %s)', signum)
        server.shutdown_flag.set()
        server.shutdown()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info('Remote client listening on https://%s:%s', config['listen_host'], config['listen_port'])
    try:
        server.serve_forever()
    finally:
        server.server_close()
        logger.info('Service stopped')

if __name__ == '__main__':
    main()
"""

SYSTEMD_TEMPLATE = """[Unit]
Description=SSL Remote HTTPS Client Service
After=network.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={install_dir}
Environment=PYTHONUNBUFFERED=1
ExecStart={python_exec} {install_dir}/remote_client_service.py --config {install_dir}/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def check_root():
    if os.geteuid() != 0:
        print('ההתקנה חייבת לרוץ כ-root (sudo).', file=sys.stderr)
        sys.exit(1)


def ensure_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def run_command(cmd, **kwargs):
    logging.debug('Running command: %s', ' '.join(cmd))
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
    if result.stdout:
        logging.debug(result.stdout.strip())
    if result.stderr:
        logging.debug(result.stderr.strip())
    return result


def generate_self_signed(cert_path: Path, key_path: Path, cn: str):
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('לא נמצא OpenSSL במערכת. ספק קבצי תעודה קיימים או התקן openssl')
    cmd = [
        openssl,
        'req',
        '-x509',
        '-nodes',
        '-newkey', 'rsa:2048',
        '-keyout', str(key_path),
        '-out', str(cert_path),
        '-days', '825',
        '-subj', f'/CN={cn}',
    ]
    run_command(cmd)
    key_path.chmod(0o600)
    cert_path.chmod(0o644)


def write_file(path: Path, content: str, mode: int = 0o644):
    path.write_text(content, encoding='utf-8')
    path.chmod(mode)


def write_json(path: Path, data: Dict[str, Any], mode: int = 0o600):
    with path.open('w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    path.chmod(mode)


def install_service(args):
    check_root()
    install_dir = Path(args.install_dir).expanduser().resolve()
    ensure_directory(install_dir)
    if args.listen_port <= 0 or args.listen_port > 65535:
        raise SystemExit('פורט ההאזנה חייב להיות בין 1 ל-65535')
    if args.workers <= 0:
        raise SystemExit('יש להזין מספר עובדים גדול מ-0')
    if bool(args.cert_file) ^ bool(args.key_file):
        raise SystemExit('אם מספקים תעודה קיימת יש למסור גם קובץ מפתח פרטי ולהיפך')

    cert_path = Path(args.cert_file).resolve() if args.cert_file else install_dir / 'remote-client.crt'
    key_path = Path(args.key_file).resolve() if args.key_file else install_dir / 'remote-client.key'

    if args.cert_file and args.key_file:
        shutil.copy2(args.cert_file, cert_path)
        shutil.copy2(args.key_file, key_path)
        key_path.chmod(0o600)
    else:
        cn = args.common_name or args.listen_host or socket.gethostname()
        generate_self_signed(cert_path, key_path, cn)

    service_script = install_dir / 'remote_client_service.py'
    write_file(service_script, SERVICE_SCRIPT, 0o755)

    if args.log_file:
        log_path = Path(args.log_file)
        if not log_path.parent.exists():
            ensure_directory(log_path.parent)
        if not log_path.exists():
            log_path.touch()
        log_path.chmod(0o664)
    else:
        log_path = install_dir / 'remote-client.log'
        if not log_path.exists():
            log_path.touch()
        log_path.chmod(0o664)

    config = {
        'listen_host': args.listen_host,
        'listen_port': args.listen_port,
        'auth_token': args.auth_token,
        'tls_cert': str(cert_path),
        'tls_key': str(key_path),
        'log_path': str(log_path),
        'verify_callback': not args.insecure_callback,
        'workers': args.workers,
        'connect_timeout': args.connect_timeout,
        'report_timeout': args.report_timeout,
    }
    config_path = install_dir / 'config.json'
    write_json(config_path, config)

    python_exec = shutil.which('python3') or sys.executable
    service_unit = SYSTEMD_TEMPLATE.format(
        user=args.user,
        group=args.group,
        install_dir=str(install_dir),
        python_exec=python_exec,
    )
    unit_path = Path('/etc/systemd/system') / f"{args.service_name}.service"
    write_file(unit_path, service_unit, 0o644)

    try:
        shutil.chown(install_dir, user=args.user, group=args.group)
        shutil.chown(service_script, user=args.user, group=args.group)
        shutil.chown(config_path, user=args.user, group=args.group)
        shutil.chown(cert_path, user=args.user, group=args.group)
        shutil.chown(key_path, user=args.user, group=args.group)
        shutil.chown(log_path, user=args.user, group=args.group)
    except PermissionError:
        pass

    run_command(['systemctl', 'daemon-reload'])
    run_command(['systemctl', 'enable', args.service_name])
    run_command(['systemctl', 'restart', args.service_name])

    summary = textwrap.dedent(f"""
    ✔ הסרוויס הותקן והופעל.
      • קובץ קונפיגורציה: {config_path}
      • קבצי תעודה: {cert_path}, {key_path}
      • לוגים: {log_path}
      • בדיקת סטטוס: sudo systemctl status {args.service_name}
      • צפייה בלוג: sudo journalctl -u {args.service_name} -f
    """)
    print(summary)


def build_parser():
    parser = argparse.ArgumentParser(description='התקנת סרוויס לקליינט ה-HTTPS המרוחק עבור SSL Expiry Manager')
    parser.add_argument('--install-dir', default='/opt/ssl_remote_client', help='תיקיית התקנה (ברירת מחדל: /opt/ssl_remote_client)')
    parser.add_argument('--service-name', default='ssl-remote-client', help='שם הסרוויס במערכת (systemd)')
    parser.add_argument('--listen-host', default='0.0.0.0', help='כתובת להאזנה (ברירת מחדל: כל הממשקים)')
    parser.add_argument('--listen-port', type=int, default=8443, help='פורט להאזנה (ברירת מחדל: 8443)')
    parser.add_argument('--auth-token', required=True, help='טוקן אימות שיתווסף לכותרת Authorization בבקשות מהוורדפרס')
    parser.add_argument('--user', default='root', help='משתמש שיריץ את הסרוויס (ברירת מחדל: root)')
    parser.add_argument('--group', default='root', help='קבוצת הסרוויס (ברירת מחדל: root)')
    parser.add_argument('--cert-file', help='נתיב לתעודת TLS קיימת (אופציונלי)')
    parser.add_argument('--key-file', help='נתיב למפתח פרטי קיים (אופציונלי)')
    parser.add_argument('--common-name', help='Common Name ליצירת תעודה עצמית במידה ולא מסופקת תעודה')
    parser.add_argument('--log-file', default='/var/log/ssl_remote_client.log', help='נתיב ללוג הסרוויס')
    parser.add_argument('--workers', type=int, default=4, help='מספר תהליכי המשנה לבדיקות במקביל (ברירת מחדל: 4)')
    parser.add_argument('--connect-timeout', type=int, default=15, help='זמן המתנה מרבי (שניות) לחיבור לשרת היעד')
    parser.add_argument('--report-timeout', type=int, default=20, help='Timeout (שניות) לדיווח תוצאה חזרה ל-WordPress')
    parser.add_argument('--insecure-callback', action='store_true', help='בטל בדיקת TLS בעת שליחת הדוח ל-WordPress (לא מומלץ)')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    install_service(args)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
