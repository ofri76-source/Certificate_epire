# SSLAgent service (no pywin32)
import os
import time
import json
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
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

config_server_base = ''


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


def build_endpoint(base, suffix):
    base = (base or '').rstrip('/')
    suffix = (suffix or '').lstrip('/')
    if not base:
        return '/' + suffix
    return base + '/' + suffix


def parse_site_url(site_url):
    raw = (site_url or '').strip()
    if not raw:
        raise ValueError('site_url is empty')
    if '://' not in raw:
        raw = 'https://' + raw
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        raise ValueError('cannot determine host from %r' % (site_url,))
    scheme = (parsed.scheme or 'https').lower()
    if scheme == 'http':
        scheme = 'https'
    if scheme not in ('https', 'ssl', 'tls'):
        raise ValueError('unsupported scheme %s' % scheme)
    port = parsed.port or 443
    return host, port, scheme, parsed.geturl()


def fetch_certificate(host, port, timeout=20):
    start = time.time()
    cert = None
    status = 'ok'
    error = ''
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        status = 'verify_error'
        error = getattr(exc, 'verify_message', str(exc))
        try:
            insecure = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with insecure.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
        except Exception as fallback_exc:
            if error:
                error = '%s; %s' % (error, fallback_exc)
            else:
                error = str(fallback_exc)
    except Exception as exc:
        status = 'connection_error'
        error = str(exc)
    latency_ms = int((time.time() - start) * 1000)
    return {
        'certificate': cert,
        'status': status,
        'error': error,
        'latency_ms': latency_ms,
    }


def extract_cert_metadata(cert):
    info = {}
    if not cert:
        return info
    not_after = cert.get('notAfter')
    if not_after:
        try:
            expiry_seconds = ssl.cert_time_to_seconds(not_after)
            info['expiry_ts'] = int(expiry_seconds)
            info['not_after'] = not_after
        except Exception:
            info['not_after'] = not_after
    subject = cert.get('subject', ())
    for rdn in subject:
        for key, value in rdn:
            if key.lower() == 'commonname':
                info['common_name'] = value
                break
        if 'common_name' in info:
            break
    issuer_parts = []
    issuer = cert.get('issuer', ())
    for rdn in issuer:
        for key, value in rdn:
            if key.lower() in ('organizationname', 'commonname'):
                issuer_parts.append(value)
    if issuer_parts:
        seen = []
        for part in issuer_parts:
            if part not in seen:
                seen.append(part)
        info['issuer_name'] = ', '.join(seen)
    alt_names = []
    for entry in cert.get('subjectAltName', ()):  # type: ignore[arg-type]
        if len(entry) >= 2 and entry[0].lower() == 'dns':
            alt_names.append(entry[1])
    if alt_names:
        info['subject_alt_names'] = alt_names
    return info


def poll_jobs(session, base, headers):
    url = build_endpoint(base, 'poll')
    try:
        response = session.get(url, headers=headers, timeout=30)
    except Exception as exc:
        log.error('poll request failed: %s', exc)
        return []
    if response.status_code != 200:
        text = response.text[:200] if hasattr(response, 'text') else ''
        log.warning('poll status=%s body=%s', response.status_code, text)
        return []
    try:
        data = response.json()
    except ValueError as exc:
        log.error('poll JSON decode failed: %s', exc)
        return []
    jobs = data.get('tasks') or data.get('jobs') or []
    if not isinstance(jobs, list):
        log.warning('unexpected poll payload: %s', jobs)
        return []
    return jobs


def ack_jobs(session, base, headers, jobs):
    payload = []
    for job in jobs:
        job_id = job.get('id')
        if not job_id:
            continue
        entry = {'id': job_id}
        if job.get('request_id'):
            entry['request_id'] = job['request_id']
        payload.append(entry)
    if not payload:
        return
    url = build_endpoint(base, 'ack')
    try:
        response = session.post(url, headers=headers, json={'tasks': payload}, timeout=30)
    except Exception as exc:
        log.error('ack request failed: %s', exc)
        return
    if response.status_code != 200:
        log.warning('ack status=%s body=%s', response.status_code, response.text[:200])


def post_results(session, endpoint, headers, results):
    if not results:
        return
    try:
        response = session.post(endpoint, headers=headers, json={'results': results}, timeout=30)
    except Exception as exc:
        log.error('report request failed for %s: %s', endpoint, exc)
        return
    if response.status_code != 200:
        log.warning('report status=%s body=%s', response.status_code, response.text[:200])


def build_job_result(job):
    job_id = job.get('id')
    site_url = job.get('site_url') or ''
    callback = job.get('callback')
    base = config_server_base or ''
    executed_at = datetime.utcnow().replace(microsecond=0, tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    try:
        host, port, scheme, normalized_url = parse_site_url(site_url)
    except ValueError as exc:
        message = str(exc)
        log.error('job %s invalid url: %s', job_id, message)
        result = {
            'id': job_id,
            'request_id': job.get('request_id'),
            'site_url': site_url,
            'check_name': job.get('client_name') or site_url or str(job_id),
            'status': 'invalid_url',
            'error': message,
            'executed_at': executed_at,
            'source': 'agent',
            'initiator': 'python-agent',
        }
        return result, callback or build_endpoint(base, 'report')

    fetch = fetch_certificate(host, port)
    metadata = extract_cert_metadata(fetch.get('certificate'))
    if fetch.get('error'):
        log.warning('job %s %s:%s error: %s', job_id, host, port, fetch['error'])
    else:
        log.info('job %s fetched certificate for %s:%s', job_id, host, port)
    result = {
        'id': job_id,
        'request_id': job.get('request_id'),
        'site_url': site_url,
        'check_name': job.get('client_name') or normalized_url or host,
        'status': fetch.get('status', 'unknown'),
        'latency_ms': fetch.get('latency_ms'),
        'executed_at': executed_at,
        'source': 'agent',
        'initiator': 'python-agent',
        'target_host': host,
        'target_port': port,
        'scheme': scheme,
    }
    if job.get('context'):
        result['context'] = job['context']
    if fetch.get('error'):
        result['error'] = fetch['error']
    for key in ('expiry_ts', 'not_after', 'common_name', 'issuer_name', 'subject_alt_names'):
        if key in metadata:
            result[key] = metadata[key]
    return result, callback or build_endpoint(base, 'report')


def once():
    c=load_cfg(); s=sess()
    if s is None:
        log.warning("requests module missing; skipping poll")
        return
    global config_server_base
    config_server_base = c['server_base']
    hdr={"X-Agent-Token": c["token"], "Content-Type":"application/json"}
    jobs = poll_jobs(s, config_server_base, hdr)
    if not jobs:
        if c.get('verbose'):
            log.debug('no jobs available')
        return
    log.info('received %s job(s)', len(jobs))
    ack_jobs(s, config_server_base, hdr, jobs)
    grouped = {}
    for job in jobs:
        result, endpoint = build_job_result(job)
        grouped.setdefault(endpoint, []).append(result)
    for endpoint, results in grouped.items():
        post_results(s, endpoint, hdr, results)


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
