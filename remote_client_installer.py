#!/usr/bin/env python3
"""Installer for the SSL remote polling client service.

This script provisions a systemd service that continuously polls the
WordPress REST API (/ssl-agent/v1/poll) and reports certificate results
back to /ssl-agent/v1/report using the configured X-Agent-Token header.
"""
import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict
from urllib import parse as urllib_parse

SERVICE_SCRIPT = """#!/usr/bin/env python3
import argparse
import json
import logging
import logging.handlers
import queue
import signal
import ssl
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List
from urllib import error as urllib_error, parse as urllib_parse, request as urllib_request
import socket

USER_AGENT = 'ssl-remote-client/1.1'


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


def poll_tasks(runtime) -> List[Dict[str, Any]]:
    url = runtime.poll_url
    if runtime.batch_limit:
        sep = '&' if '?' in url else '?'
        url = f"{url}{sep}limit={runtime.batch_limit}"
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json',
        'X-Agent-Token': runtime.agent_token,
    }
    request = urllib_request.Request(url, headers=headers, method='GET')
    context = runtime.wp_context if url.startswith('https://') else None
    with urllib_request.urlopen(request, timeout=runtime.report_timeout, context=context) as resp:
        body = resp.read().decode('utf-8')
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'Invalid JSON response: {exc}')
    tasks = []
    for item in data.get('tasks') or []:
        try:
            job_id = int(item.get('id'))
        except (TypeError, ValueError):
            continue
        site_url = (item.get('site_url') or '').strip()
        if not site_url:
            continue
        request_id = (item.get('request_id') or '').strip() or f"req-{int(time.time()*1000)}"
        job = {
            'id': job_id,
            'site_url': site_url,
            'context': str(item.get('context') or 'unknown').strip(),
            'request_id': request_id,
            'callback': str(item.get('callback') or runtime.report_url).strip() or runtime.report_url,
        }
        tasks.append(job)
    return tasks


def send_report(runtime, job: Dict[str, Any], result: Dict[str, Any]) -> bool:
    payload = json.dumps({'results': [result]}).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': USER_AGENT,
        'X-Agent-Token': runtime.agent_token,
    }
    target = (job.get('callback') or runtime.report_url).strip() or runtime.report_url
    request = urllib_request.Request(target, data=payload, headers=headers, method='POST')
    context = runtime.wp_context if target.startswith('https://') else None
    try:
        with urllib_request.urlopen(request, timeout=runtime.report_timeout, context=context) as resp:
            resp.read()
        return True
    except urllib_error.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='ignore') if hasattr(exc, 'read') else ''
        runtime.logger.error('Report HTTP error %s: %s', exc.code, body)
    except Exception as exc:  # pragma: no cover - network failures
        runtime.logger.error('Report error: %s', exc)
    return False


class Poller(threading.Thread):
    daemon = True

    def __init__(self, runtime):
        super().__init__(daemon=True)
        self.runtime = runtime

    def run(self):
        runtime = self.runtime
        runtime.logger.info('Polling endpoint: %s', runtime.poll_url)
        while not runtime.shutdown_flag.is_set():
            start = time.time()
            had_tasks = False
            try:
                tasks = poll_tasks(runtime)
                if tasks:
                    had_tasks = True
                    for job in tasks:
                        try:
                            runtime.queue.put_nowait(job)
                        except queue.Full:
                            runtime.logger.error('Local queue full, dropping job %s', job.get('id'))
                    runtime.logger.debug('Fetched %s tasks from server', len(tasks))
            except urllib_error.HTTPError as exc:
                body = exc.read().decode('utf-8', errors='ignore') if hasattr(exc, 'read') else ''
                runtime.logger.error('Poll HTTP error %s: %s', exc.code, body)
            except Exception as exc:  # pragma: no cover - defensive
                runtime.logger.error('Poll error: %s', exc)
            elapsed = time.time() - start
            sleep_for = 1 if had_tasks else max(1, runtime.poll_interval - int(elapsed))
            end_time = time.time() + sleep_for
            while time.time() < end_time:
                if runtime.shutdown_flag.is_set():
                    break
                time.sleep(0.2)


class Worker(threading.Thread):
    daemon = True

    def __init__(self, runtime, index):
        super().__init__(daemon=True)
        self.runtime = runtime
        self.name = f'worker-{index}'

    def run(self):
        runtime = self.runtime
        q = runtime.queue
        while not runtime.shutdown_flag.is_set():
            try:
                job = q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                runtime.logger.info('Processing #%s (%s)', job['id'], job.get('context', ''))
                result: Dict[str, Any] = {
                    'id': job['id'],
                    'request_id': job.get('request_id'),
                }
                try:
                    expiry_ts = fetch_expiry_timestamp(job['site_url'], runtime.connect_timeout)
                    result['expiry_ts'] = expiry_ts
                except Exception as exc:  # pragma: no cover - network failures
                    runtime.logger.error('Fetch failed for %s: %s', job['site_url'], exc)
                    result['error'] = str(exc)
                success = send_report(runtime, job, result)
                if success:
                    runtime.logger.info('Reported #%s successfully', job['id'])
                else:
                    runtime.logger.error('Failed to report result for #%s', job['id'])
            finally:
                q.task_done()


class Runtime:
    def __init__(self, config: Dict[str, Any]):
        self.logger = setup_logger(config['log_path'])
        self.queue: queue.Queue = queue.Queue(maxsize=5000)
        self.shutdown_flag = threading.Event()
        self.agent_token = config['agent_token']
        self.poll_url = config['poll_url']
        self.report_url = config['report_url']
        self.poll_interval = int(config.get('poll_interval', 30))
        self.connect_timeout = int(config.get('connect_timeout', 15))
        self.report_timeout = int(config.get('report_timeout', 20))
        self.batch_limit = int(config.get('batch_limit', 25))
        verify_wp = bool(config.get('verify_wp', True))
        self.wp_context = ssl.create_default_context() if verify_wp else ssl._create_unverified_context()


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
    runtime = Runtime(config)
    workers = []
    for index in range(max(1, int(config.get('workers', 4)))):
        worker = Worker(runtime, index + 1)
        worker.start()
        workers.append(worker)
    poller = Poller(runtime)
    poller.start()

    def handle_signal(signum, frame):  # pragma: no cover - runtime
        runtime.logger.info('Stopping service (signal %s)', signum)
        runtime.shutdown_flag.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    runtime.logger.info('Remote agent started with %s workers', len(workers))
    try:
        while not runtime.shutdown_flag.is_set():
            time.sleep(1)
    finally:
        poller.join(timeout=2)
        for worker in workers:
            worker.join(timeout=2)
        runtime.logger.info('Service stopped')


if __name__ == '__main__':
    main()
"""

SYSTEMD_TEMPLATE = """[Unit]
Description=SSL Remote Polling Client Service
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


def write_file(path: Path, content: str, mode: int = 0o644):
    path.write_text(content, encoding='utf-8')
    path.chmod(mode)


def write_json(path: Path, data: Dict[str, Any], mode: int = 0o600):
    with path.open('w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    path.chmod(mode)


def normalize_wp_url(url: str) -> str:
    url = (url or '').strip()
    if not url:
        raise SystemExit('יש להזין כתובת WordPress חוקית באמצעות --wp-url')
    if '://' not in url:
        url = 'https://' + url
    parsed = urllib_parse.urlparse(url)
    if parsed.scheme not in ('https', 'http'):
        raise SystemExit('הכתובת חייבת להתחיל ב-http:// או https://')
    if not parsed.netloc:
        raise SystemExit('הכתובת שסופקה אינה תקינה')
    return url.rstrip('/')


def install_service(args):
    check_root()
    install_dir = Path(args.install_dir).expanduser().resolve()
    ensure_directory(install_dir)

    if args.workers <= 0:
        raise SystemExit('יש להזין מספר עובדים גדול מ-0')
    if args.poll_interval <= 0:
        raise SystemExit('יש להזין poll-interval גדול מ-0')

    wp_url = normalize_wp_url(args.wp_url)
    poll_url = urllib_parse.urljoin(wp_url + '/', 'wp-json/ssl-agent/v1/poll')
    report_url = urllib_parse.urljoin(wp_url + '/', 'wp-json/ssl-agent/v1/report')

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
        'wp_url': wp_url,
        'poll_url': poll_url,
        'report_url': report_url,
        'agent_token': args.agent_token,
        'verify_wp': not args.insecure_wp,
        'poll_interval': args.poll_interval,
        'workers': args.workers,
        'connect_timeout': args.connect_timeout,
        'report_timeout': args.report_timeout,
        'batch_limit': args.batch_limit,
        'log_path': str(log_path),
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
        shutil.chown(log_path, user=args.user, group=args.group)
    except PermissionError:
        pass

    run_command(['systemctl', 'daemon-reload'])
    run_command(['systemctl', 'enable', args.service_name])
    run_command(['systemctl', 'restart', args.service_name])

    summary = textwrap.dedent(f"""
    ✔ הסרוויס הותקן והופעל.
      • קובץ קונפיגורציה: {config_path}
      • כתובת Poll: {poll_url}
      • כתובת Report: {report_url}
      • לוגים: {log_path}
      • בדיקת סטטוס: sudo systemctl status {args.service_name}
      • צפייה בלוג: sudo journalctl -u {args.service_name} -f
    """)
    print(summary)


def build_parser():
    parser = argparse.ArgumentParser(description='התקנת סרוויס לסוכן ה-SSL המרוחק (Polling) עבור SSL Expiry Manager')
    parser.add_argument('--install-dir', default='/opt/ssl_remote_client', help='תיקיית התקנה (ברירת מחדל: /opt/ssl_remote_client)')
    parser.add_argument('--service-name', default='ssl-remote-client', help='שם הסרוויס במערכת (systemd)')
    parser.add_argument('--wp-url', required=True, help='כתובת אתר ה-WordPress (לדוגמה: https://kb.example.com)')
    parser.add_argument('--agent-token', required=True, help='ערך הטוקן שיוגדר בכותרת X-Agent-Token')
    parser.add_argument('--poll-interval', type=int, default=30, help='מרווח (שניות) בין בקשות poll (ברירת מחדל: 30)')
    parser.add_argument('--batch-limit', type=int, default=25, help='מספר המשימות המרבי למשיכה בכל poll (ברירת מחדל: 25)')
    parser.add_argument('--workers', type=int, default=4, help='מספר תהליכי המשנה לבדיקות במקביל (ברירת מחדל: 4)')
    parser.add_argument('--connect-timeout', type=int, default=15, help='זמן המתנה מרבי (שניות) לחיבור לשרת היעד')
    parser.add_argument('--report-timeout', type=int, default=20, help='Timeout (שניות) לשליחת דוח בחזרה ל-WordPress')
    parser.add_argument('--insecure-wp', action='store_true', help='בטל אימות TLS מול WordPress (לא מומלץ)')
    parser.add_argument('--log-file', default='/var/log/ssl_remote_client.log', help='נתיב ללוג הסרוויס')
    parser.add_argument('--user', default='root', help='משתמש שיריץ את הסרוויס (ברירת מחדל: root)')
    parser.add_argument('--group', default='root', help='קבוצת הסרוויס (ברירת מחדל: root)')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    install_service(args)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
