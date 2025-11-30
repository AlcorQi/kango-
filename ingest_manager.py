import os
import json
import time
import socket
import hashlib
import smtplib
import threading
from email.message import EmailMessage
from config import DATA_DIR, CONFIG_FILE, ANOMALIES_FILE, SCHEMA_VERSION

OFFSETS_FILE = os.path.join(DATA_DIR, 'ingest_offsets.json')
ALERT_STATE_FILE = os.path.join(DATA_DIR, 'alert_state.json')

ingest_started = False
cleanup_started = False
last_scan_ts = None
alert_state = {}

def _load_offsets():
    """加载文件偏移量"""
    try:
        with open(OFFSETS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def _save_offsets(o):
    """保存文件偏移量"""
    try:
        with open(OFFSETS_FILE, 'w', encoding='utf-8') as f:
            json.dump(o, f)
    except:
        pass

def _load_alert_state():
    """加载告警状态"""
    try:
        with open(ALERT_STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def _save_alert_state(s):
    """保存告警状态"""
    try:
        with open(ALERT_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(s, f)
    except:
        pass

def _send_email(to_addr, subject, body):
    """发送邮件"""
    host = os.environ.get('SMTP_HOST')
    port = int(os.environ.get('SMTP_PORT', '25'))
    user = os.environ.get('SMTP_USER')
    pwd = os.environ.get('SMTP_PASS')
    sender = os.environ.get('SMTP_FROM', user or 'noreply@example.com')
    if not host or not to_addr:
        return False
    try:
        msg = EmailMessage()
        msg['From'] = sender
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            if os.environ.get('SMTP_TLS') == '1':
                smtp.starttls()
            if user and pwd:
                smtp.login(user, pwd)
            smtp.send_message(msg)
        return True
    except:
        return False

def _handle_alert(ev, cfg):
    """处理告警"""
    alerts = cfg.get('alerts', {})
    if not alerts.get('enabled'):
        return
    emails = alerts.get('emails') or []
    to = emails[0] if emails else None
    if not to:
        return
    sev = ev.get('severity')
    t = ev.get('type')
    msg = ev.get('message') or ''
    key_raw = f"{sev}|{t}|{msg[:120]}".encode('utf-8', 'ignore')
    key = hashlib.sha256(key_raw).hexdigest()
    now = time.time()
    silent_min = int(alerts.get('silent_minutes', 30))
    last_ts = alert_state.get(key)
    if not (sev == 'critical' and alerts.get('notify_critical', True)):
        if last_ts and (now - float(last_ts)) < max(0, silent_min) * 60:
            return
    subject = f"[{sev}] {t}"
    body = (
        f"Type: {t}\n"
        f"Severity: {sev}\n"
        f"Detected At: {ev.get('detected_at')}\n"
        f"Host: {ev.get('host_id')}\n"
        f"Source: {ev.get('source_file')}:{ev.get('line_number')}\n\n"
        f"Message:\n{msg}\n"
    )
    if _send_email(to, subject, body):
        alert_state[key] = now
        _save_alert_state(alert_state)

def _match_types(line, enabled):
    """匹配异常类型"""
    s = line.lower()
    types = []
    if 'oom' in enabled:
        if ('out of memory' in s) or ('oom-killer' in s):
            types.append('oom')
    if 'kernel_panic' in enabled:
        if 'kernel panic' in s:
            types.append('kernel_panic')
    if 'unexpected_reboot' in enabled:
        if ('reboot' in s) or ('booting' in s):
            types.append('unexpected_reboot')
    if 'fs_error' in enabled:
        if ('fs error' in s) or ('i/o error' in s) or ('filesystem corruption' in s) or ('ext4-fs error' in s) or ('xfs error' in s):
            types.append('fs_error')
    if 'oops' in enabled:
        if 'oops:' in s:
            types.append('oops')
    if 'deadlock' in enabled:
        if ('deadlock' in s) or ('recursive locking' in s):
            types.append('deadlock')
    return types

def _severity_for(t):
    """获取异常类型的严重程度"""
    return {
        'kernel_panic': 'critical',
        'oom': 'major',
        'unexpected_reboot': 'major',
        'fs_error': 'major',
        'oops': 'minor',
        'deadlock': 'major'
    }.get(t, 'minor')

def _write_event(ev):
    """写入事件"""
    try:
        with open(ANOMALIES_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(ev) + "\n")
    except:
        pass

def _is_log_like(name):
    """判断是否为日志文件"""
    lower = name.lower()
    if lower.endswith('.log'):
        return True
    if '.log.' in lower:
        return True
    bases = {
        'syslog','messages','kern.log','dmesg','auth.log','daemon.log',
        'boot.log','cron','xorg.log','yum.log','pacman.log','dpkg.log','audit.log'
    }
    return any(lower.startswith(b) for b in bases) or lower.endswith('.gz')

def _is_excluded_binary(name):
    """判断是否为排除的二进制文件"""
    lower = name.lower()
    for ex in ('lastlog','wtmp','btmp','faillog','utmp'):
        if lower.startswith(ex):
            return True
    return False

def _collect_paths(paths):
    """收集日志文件路径"""
    files = []
    for p in paths or []:
        ap = os.path.abspath(p)
        if os.path.isfile(ap):
            files.append(ap)
        elif os.path.isdir(ap):
            for root, dirs, filenames in os.walk(ap):
                parts = root.replace('\\','/').split('/')
                if 'journal' in parts:
                    continue
                for name in filenames:
                    if _is_excluded_binary(name):
                        continue
                    if _is_log_like(name):
                        files.append(os.path.join(root, name))
    return files

def ingest_loop():
    """日志摄取循环"""
    global ingest_started, last_scan_ts
    if ingest_started:
        return
    ingest_started = True
    offsets = _load_offsets()
    while True:
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except:
            cfg = {}
        det = cfg.get('detection', {})
        interval = int(det.get('scan_interval_sec', 60))
        paths = det.get('log_paths', [])
        enabled = det.get('enabled_detectors', [])
        files = _collect_paths(paths)
        try:
            last_scan_ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        except:
            pass
        for fp in files:
            try:
                if fp.endswith('.gz'):
                    continue
                sz = os.path.getsize(fp)
                off = int(offsets.get(fp, 0))
                if off > sz or off < 0:
                    off = 0
                with open(fp, 'r', errors='ignore') as f:
                    f.seek(off)
                    ln = off
                    line_no = 0
                    for line in f:
                        line_no += 1
                        ln += len(line.encode('utf-8', 'ignore'))
                        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                        types = _match_types(line, enabled)
                        for t in types:
                            raw = (socket.gethostname() + fp + str(line_no) + ts + line).encode('utf-8', 'ignore')
                            eid = hashlib.sha256(raw).hexdigest()[:16]
                            ev = {
                                "schema_version": SCHEMA_VERSION,
                                "id": eid,
                                "type": t,
                                "severity": _severity_for(t),
                                "message": line.strip(),
                                "source_file": fp,
                                "line_number": line_no,
                                "detected_at": ts,
                                "host_id": socket.gethostname(),
                                "processed": False
                            }
                            _write_event(ev)
                            try:
                                _handle_alert(ev, cfg)
                            except:
                                pass
                    offsets[fp] = ln
            except:
                continue
        _save_offsets(offsets)
        time.sleep(max(5, min(3600, interval)))

def cleanup_loop():
    """清理循环"""
    global cleanup_started
    if cleanup_started:
        return
    cleanup_started = True
    while True:
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except:
            cfg = {}
        det = cfg.get('detection', {})
        rd = int(det.get('retention_days', 30))
        rmax = int(det.get('retention_max_events', 50000))
        cutoff = time.time() - rd * 86400
        try:
            keep = []
            with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        ev = json.loads(s)
                    except:
                        continue
                    ts = ev.get('detected_at')
                    try:
                        t = time.strptime(ts, '%Y-%m-%dT%H:%M:%SZ') if ts else None
                        te = time.mktime(t) if t else None
                    except:
                        te = None
                    if te is None or te >= cutoff:
                        keep.append((te or 0, s))
            keep.sort(key=lambda x: x[0])
            if rmax and len(keep) > rmax:
                keep = keep[-rmax:]
            with open(ANOMALIES_FILE, 'w', encoding='utf-8') as f:
                for _, s in keep:
                    f.write(s + "\n")
        except:
            pass
        try:
            day_dir = os.path.join(DATA_DIR, 'anomalies')
            if os.path.isdir(day_dir):
                for name in os.listdir(day_dir):
                    if not name.endswith('.ndjson'):
                        continue
                    base = name[:-7]
                    try:
                        t = time.strptime(base, '%Y-%m-%d')
                        te = time.mktime(t)
                    except:
                        continue
                    if te < cutoff:
                        try:
                            os.remove(os.path.join(day_dir, name))
                        except:
                            pass
        except:
            pass
        time.sleep(3600)  # 每小时清理一次

def init_alert_state():
    """初始化告警状态"""
    global alert_state
    alert_state = _load_alert_state()

