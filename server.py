import os
import json
import time
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(ROOT, 'web')
DATA_DIR = os.path.join(ROOT, 'data')
CONFIG_DIR = os.path.join(ROOT, 'config')
ANOMALIES_FILE = os.path.join(DATA_DIR, 'anomalies.ndjson')
SUMMARY_FILE = os.path.join(DATA_DIR, 'summary.json')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')

SCHEMA_VERSION = "1.0"

clients_lock = threading.Lock()
clients = set()
tailer_started = False
heartbeat_started = False

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(ANOMALIES_FILE):
        with open(ANOMALIES_FILE, 'a', encoding='utf-8'):
            pass
    if not os.path.exists(SUMMARY_FILE):
        with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                "schema_version": SCHEMA_VERSION,
                "date": time.strftime('%Y-%m-%d', time.gmtime()),
                "total_anomalies": 0,
                "by_severity": {"critical": 0, "major": 0, "minor": 0},
                "by_type": {},
                "hosts": [],
                "trend": []
            }, f)
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                "schema_version": SCHEMA_VERSION,
                "detection": {
                    "log_paths": ["/var/log", "/opt/app/logs"],
                    "scan_interval_sec": 60,
                    "retention_days": 30,
                    "enabled_detectors": ["oom","kernel_panic","unexpected_reboot","fs_error","oops","deadlock"]
                },
                "alerts": {
                    "enabled": False,
                    "emails": [],
                    "notify_critical": True,
                    "silent_minutes": 30
                },
                "ui": {
                    "auto_refresh_sec": 30,
                    "page_size": 20,
                    "time_format": "24h"
                },
                "security": {
                    "ingest_token": "<redacted>",
                    "sse_max_clients": 100
                }
            }, f)

def read_summary():
    with open(SUMMARY_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_summary(s):
    with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
        json.dump(s, f)

def iter_anomalies():
    with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except:
                continue

def compute_stats(window=None):
    total = 0
    by_severity = {"critical": 0, "major": 0, "minor": 0}
    by_type = {}
    last_detection = None
    now = time.time()
    window_sec = None
    if window:
        try:
            if window.startswith('PT') and window.endswith('H'):
                window_sec = int(window[2:-1]) * 3600
            elif window.endswith('h'):
                window_sec = int(window[:-1]) * 3600
        except:
            window_sec = None
    for ev in iter_anomalies():
        try:
            ts = time.strptime(ev.get('detected_at'), '%Y-%m-%dT%H:%M:%SZ')
            ts_epoch = time.mktime(ts)
        except:
            ts_epoch = None
        if window_sec is not None and ts_epoch is not None:
            if (now - ts_epoch) > window_sec:
                continue
        total += 1
        sev = ev.get('severity')
        if sev in by_severity:
            by_severity[sev] += 1
        t = ev.get('type')
        if t:
            by_type[t] = by_type.get(t, 0) + 1
        if ev.get('detected_at'):
            if not last_detection or ev['detected_at'] > last_detection:
                last_detection = ev['detected_at']
    return {
        "schema_version": SCHEMA_VERSION,
        "total_anomalies": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "trend": [],
        "last_detection": last_detection
    }

def parse_iso(s):
    try:
        return time.strptime(s, '%Y-%m-%dT%H:%M:%SZ')
    except:
        return None

def json_response(handler, obj, status=200):
    body = json.dumps(obj).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

def error_response(handler, status, code, message, details=None):
    json_response(handler, {
        "status": status,
        "code": code,
        "message": message,
        "trace_id": "",
        "details": details or {}
    }, status=status)

def publish_event(ev):
    data = json.dumps({
        "id": ev.get('id'),
        "type": ev.get('type'),
        "severity": ev.get('severity'),
        "message": ev.get('message'),
        "detected_at": ev.get('detected_at'),
        "host_id": ev.get('host_id'),
        "source_file": ev.get('source_file')
    })
    payload = (f"id: {ev.get('id')}\n" +
               "event: anomaly\n" +
               f"data: {data}\n\n").encode('utf-8')
    with clients_lock:
        for c in list(clients):
            try:
                c.wfile.write(payload)
                c.wfile.flush()
            except:
                try:
                    clients.remove(c)
                except:
                    pass

def heartbeat_loop():
    global heartbeat_started
    if heartbeat_started:
        return
    heartbeat_started = True
    while True:
        data = json.dumps({"ts": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}).encode('utf-8')
        payload = b"event: ping\n" + b"data: " + data + b"\n\n"
        with clients_lock:
            for c in list(clients):
                try:
                    c.wfile.write(payload)
                    c.wfile.flush()
                except:
                    try:
                        clients.remove(c)
                    except:
                        pass
        time.sleep(15)

def tailer_loop():
    global tailer_started
    if tailer_started:
        return
    tailer_started = True
    seen = set()
    with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
        f.seek(0, os.SEEK_END)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                time.sleep(1)
                f.seek(pos)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                eid = ev.get('id')
                if eid and eid not in seen:
                    seen.add(eid)
                    publish_event(ev)
            except:
                continue

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        if p.startswith('/api/v1/'):
            if p == '/api/v1/stats':
                qs = parse_qs(parsed.query)
                window = None
                if 'window' in qs:
                    window = qs['window'][0]
                res = compute_stats(window)
                return json_response(self, res)
            if p.startswith('/api/v1/events/'):
                eid = p.split('/')[-1]
                for ev in iter_anomalies():
                    if ev.get('id') == eid:
                        obj = ev.copy()
                        obj.setdefault('raw_excerpt', [])
                        return json_response(self, obj)
                return error_response(self, 404, 'NOT_FOUND', 'event not found')
            if p == '/api/v1/events':
                qs = parse_qs(parsed.query)
                start = qs.get('start', [None])[0]
                end = qs.get('end', [None])[0]
                severities = qs.get('severity', [])
                types = qs.get('types', [None])[0]
                keyword = qs.get('keyword', [None])[0]
                host_id = qs.get('host_id', [None])[0]
                page = int(qs.get('page', ['1'])[0])
                size = int(qs.get('size', ['20'])[0])
                sort = qs.get('sort', ['detected_at:desc'])[0]
                tset = None
                if types:
                    tset = set([t.strip() for t in types.split(',') if t.strip()])
                items = []
                for ev in iter_anomalies():
                    if start and not parse_iso(start):
                        return error_response(self, 400, 'INVALID_ARGUMENT', "parameter 'start' must be ISO8601", {"param": "start"})
                    if end and not parse_iso(end):
                        return error_response(self, 400, 'INVALID_ARGUMENT', "parameter 'end' must be ISO8601", {"param": "end"})
                    if start and ev.get('detected_at') and ev['detected_at'] < start:
                        continue
                    if end and ev.get('detected_at') and ev['detected_at'] > end:
                        continue
                    if severities and ev.get('severity') not in severities:
                        continue
                    if tset and ev.get('type') not in tset:
                        continue
                    if keyword:
                        msg = (ev.get('message') or '')
                        src = (ev.get('source_file') or '')
                        if (keyword not in msg) and (keyword not in src):
                            continue
                    if host_id and ev.get('host_id') != host_id:
                        continue
                    items.append({
                        "id": ev.get('id'),
                        "type": ev.get('type'),
                        "severity": ev.get('severity'),
                        "message": ev.get('message'),
                        "source_file": ev.get('source_file'),
                        "line_number": ev.get('line_number'),
                        "detected_at": ev.get('detected_at'),
                        "host_id": ev.get('host_id')
                    })
                reverse = True
                key = 'detected_at'
                if sort:
                    try:
                        key, order = sort.split(':')
                        reverse = order == 'desc'
                    except:
                        reverse = True
                items.sort(key=lambda x: x.get(key) or '', reverse=reverse)
                total = len(items)
                start_idx = (page - 1) * size
                end_idx = start_idx + size
                page_items = items[start_idx:end_idx]
                return json_response(self, {
                    "items": page_items,
                    "page": page,
                    "size": size,
                    "total": total,
                    "has_next": end_idx < total
                })
            if p == '/api/v1/config':
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                return json_response(self, cfg)
            if p == '/api/v1/stream':
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Connection', 'keep-alive')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Headers', 'Cache-Control, Content-Type')
                self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
                self.end_headers()
                # 发送初始数据让浏览器确认连接成功
                init_data = json.dumps({"status": "connected", "ts": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}).encode('utf-8')
                self.wfile.write(b"event: open\n" + b"data: " + init_data + b"\n\n")
                self.wfile.flush()
                print(f"[DEBUG] SSE客户端连接: {self.client_address}")  # 调试信息
                with clients_lock:
                    clients.add(self)
                threading.Thread(target=heartbeat_loop, daemon=True).start()
                threading.Thread(target=tailer_loop, daemon=True).start()
                try:
                    while True:
                        time.sleep(60)
                except:
                    with clients_lock:
                        try:
                            clients.remove(self)
                            print(f"[DEBUG] SSE客户端断开: {self.client_address}")  # 调试信息
                        except:
                            pass
                return
            return error_response(self, 404, 'NOT_FOUND', 'unknown path')
        return super().do_GET()

    def do_OPTIONS(self):
        # 处理CORS预检请求
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Cache-Control')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/v1/config':
            length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(length)
            try:
                cfg = json.loads(raw.decode('utf-8'))
            except:
                return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid json')
            allowed = {"schema_version","detection","alerts","ui","security"}
            if set(cfg.keys()) - allowed:
                return error_response(self, 400, 'INVALID_ARGUMENT', 'unknown fields')
            try:
                si = cfg['detection']['scan_interval_sec']
                rd = cfg['detection']['retention_days']
                if not (5 <= si <= 3600):
                    return error_response(self, 400, 'INVALID_ARGUMENT', 'scan_interval_sec out of range')
                if not (1 <= rd <= 365):
                    return error_response(self, 400, 'INVALID_ARGUMENT', 'retention_days out of range')
            except:
                return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid detection config')
            emails = cfg.get('alerts', {}).get('emails', [])
            if emails:
                import re
                e = emails[0]
                if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', e):
                    return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid email')
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(cfg, f)
            return json_response(self, cfg)
        return error_response(self, 404, 'NOT_FOUND', 'unknown path')

def run(host='0.0.0.0', port=8000):
    ensure_dirs()
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.serve_forever()

if __name__ == '__main__':
    run()

