import json
import time
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from config import WEB_DIR, ensure_dirs, read_config, write_config, USERS_FILE
sessions = {}
from data_store import read_summary, compute_stats, iter_anomalies, parse_iso
from sse_manager import add_client, remove_client, heartbeat_loop, tailer_loop
from ai_provider import ai_provider
from response_utils import json_response, error_response
from ingest_manager import ingest_loop, cleanup_loop, init_alert_state

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        
        if p.startswith('/api/v1/'):
            if p == '/api/v1/stats':
                return self._handle_stats(parsed)
            elif p.startswith('/api/v1/events/'):
                return self._handle_get_event(p)
            elif p == '/api/v1/events':
                return self._handle_list_events(parsed)
            elif p == '/api/v1/config':
                return self._handle_get_config()
            elif p == '/api/v1/stream':
                return self._handle_sse_stream()
            elif p == '/api/v1/ai/suggestions':
                return self._handle_ai_suggestions(parsed)
            elif p == '/api/v1/hosts':
                return self._handle_list_hosts()
            elif p == '/api/v1/test-email':
                return self._handle_test_email()
            elif p == '/api/v1/me':
                return self._handle_me()
            else:
                return error_response(self, 404, 'NOT_FOUND', 'unknown path')
        
        if p in ('/', '/index.html', '/history.html', '/settings.html'):
            if not self._is_authenticated():
                self.send_response(302)
                self.send_header('Location', '/login.html')
                self.end_headers()
                return
        return super().do_GET()

    def _handle_stats(self, parsed):
        """处理统计信息请求"""
        qs = parse_qs(parsed.query)
        window = qs.get('window', [None])[0]
        host_id = qs.get('host_id', [None])[0]
        res = compute_stats(window, host_id)
        return json_response(self, res)

    def _handle_get_event(self, path):
        """处理获取单个事件请求"""
        eid = path.split('/')[-1]
        for ev in iter_anomalies():
            if ev.get('id') == eid:
                obj = ev.copy()
                obj.setdefault('raw_excerpt', [])
                return json_response(self, obj)
        return error_response(self, 404, 'NOT_FOUND', 'event not found')

    def _handle_list_events(self, parsed):
        """处理事件列表请求"""
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

    def _handle_get_config(self):
        """处理获取配置请求"""
        cfg = read_config()
        return json_response(self, cfg)

    def _handle_sse_stream(self):
        """处理 SSE 流请求"""
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
        
        print(f"[DEBUG] SSE客户端连接: {self.client_address}")
        add_client(self)
        
        # 启动后台线程
        threading.Thread(target=heartbeat_loop, daemon=True).start()
        threading.Thread(target=tailer_loop, daemon=True).start()
        
        try:
            while True:
                time.sleep(1)
        except:
            remove_client(self)
            print(f"[DEBUG] SSE客户端断开: {self.client_address}")

    def _handle_ai_suggestions(self, parsed):
        """处理 AI 建议请求"""
        qs = parse_qs(parsed.query)
        window = qs.get('window', ['PT24H'])[0]
        types = qs.get('types', [None])[0]
        host_id = qs.get('host_id', [None])[0]
        try:
            limit = int(qs.get('limit', ['10'])[0])
        except:
            limit = 10
        
        res = ai_provider.suggestions(window, types, host_id, limit)
        return json_response(self, res)
    def _handle_ai_generate(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(length) if length > 0 else b''
            payload = {}
            if raw:
                try:
                    payload = json.loads(raw.decode('utf-8'))
                except:
                    payload = {}
            window = payload.get('window')
            types = payload.get('types')
            host_id = payload.get('host_id')
            res = ai_provider.generate(window, types, host_id)
            status = {
                "status": "success" if res.get('generated') else "error",
                "generated": res.get('generated'),
                "returncode": res.get('returncode'),
                "updated_at": res.get('updated_at'),
                "report_path": res.get('report_path')
            }
            return json_response(self, status)
        except Exception as e:
            return error_response(self, 500, 'INTERNAL_ERROR', str(e))

    def _handle_ingest(self):
        """处理 Agent 上报的异常数据"""
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length == 0:
                return error_response(self, 400, 'INVALID_ARGUMENT', 'empty body')
            
            raw = self.rfile.read(length)
            data = json.loads(raw.decode('utf-8'))
            
            # 验证数据结构
            if not isinstance(data, dict):
                return error_response(self, 400, 'INVALID_ARGUMENT', 'body must be a JSON object')
            
            # 支持单个事件或事件数组
            events = data.get('events', [data]) if 'events' not in data else data['events']
            
            if not isinstance(events, list):
                return error_response(self, 400, 'INVALID_ARGUMENT', 'events must be an array')
            
            # 验证 token（可选）
            token = self.headers.get('X-Ingest-Token') or data.get('token')
            cfg = read_config()
            expected_token = cfg.get('security', {}).get('ingest_token', '<redacted>')
            if expected_token != '<redacted>' and token != expected_token:
                return error_response(self, 401, 'UNAUTHORIZED', 'invalid ingest token')
            
            # 写入事件
            from ingest_manager import _write_event
            from ingest_manager import _handle_alert
            from ingest_manager import _severity_for
            from config import SCHEMA_VERSION
            import socket
            import hashlib
            
            count = 0
            for ev in events:
                # 验证必要字段
                if not isinstance(ev, dict):
                    continue
                
                # 确保有必要的字段
                if 'type' not in ev or 'message' not in ev:
                    continue
                
                # 生成或使用提供的 ID
                if 'id' not in ev:
                    raw_id = (ev.get('host_id', socket.gethostname()) + 
                             ev.get('source_file', '') + 
                             str(ev.get('line_number', 0)) + 
                             ev.get('detected_at', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())) + 
                             ev['message']).encode('utf-8', 'ignore')
                    ev['id'] = hashlib.sha256(raw_id).hexdigest()[:16]
                
                # 确保有 schema_version
                ev['schema_version'] = ev.get('schema_version', SCHEMA_VERSION)
                
                # 确保有 severity
                if 'severity' not in ev:
                    ev['severity'] = _severity_for(ev['type'])
                
                # 确保有 detected_at
                if 'detected_at' not in ev:
                    ev['detected_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                
                # 确保有 host_id
                if 'host_id' not in ev:
                    ev['host_id'] = socket.gethostname()
                
                # 写入事件
                _write_event(ev)
                
                # 处理告警
                try:
                    _handle_alert(ev, cfg)
                except:
                    pass
                
                # 通过 SSE 推送
                from sse_manager import publish_event
                try:
                    publish_event(ev)
                except:
                    pass
                
                count += 1
            
            return json_response(self, {
                "status": "success",
                "received": len(events),
                "processed": count
            })
            
        except json.JSONDecodeError:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid json')
        except Exception as e:
            return error_response(self, 500, 'INTERNAL_ERROR', str(e))

    def _handle_list_hosts(self):
        """返回所有已注册的机器列表"""
        hosts = set()
        for ev in iter_anomalies():
            host_id = ev.get('host_id')
            if host_id:
                hosts.add(host_id)
        
        return json_response(self, {
            "hosts": sorted(list(hosts)),
            "total": len(hosts)
        })

    def _handle_test_email(self):
        try:
            cfg = read_config()
        except:
            cfg = {}
        alerts = cfg.get('alerts', {})
        emails = alerts.get('emails') or []
        to = emails[0] if emails else None
        import os
        env = {
            "smtp_host_set": bool(os.environ.get('SMTP_HOST')),
            "smtp_port": os.environ.get('SMTP_PORT') or "",
            "smtp_tls": os.environ.get('SMTP_TLS') in ('1', 'true', 'True'),
            "smtp_user_set": bool(os.environ.get('SMTP_USER')),
            "smtp_pass_set": bool(os.environ.get('SMTP_PASS')),
            "smtp_from_set": bool(os.environ.get('SMTP_FROM')),
        }
        if not to:
            return json_response(self, {"sent": False, "reason": "no_recipient", "env": env})
        from ingest_manager import _send_email
        import time
        ok = False
        try:
            ok = _send_email(to, "测试邮件", f"测试发送时间: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}")
        except:
            ok = False
        if ok:
            return json_response(self, {"sent": True, "to": to, "env": env})
        else:
            reason = "smtp_not_configured" if not env["smtp_host_set"] else "send_failed"
            return json_response(self, {"sent": False, "to": to, "reason": reason, "env": env})

    def do_OPTIONS(self):
        """处理 CORS 预检请求"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Cache-Control')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def do_POST(self):
        """处理 POST 请求"""
        parsed = urlparse(self.path)
        if parsed.path == '/api/v1/ingest':
            return self._handle_ingest()
        if parsed.path == '/api/v1/ai/generate':
            return self._handle_ai_generate()
        if parsed.path == '/api/v1/register':
            return self._handle_register()
        if parsed.path == '/api/v1/register/verify':
            return self._handle_register_verify()
        if parsed.path == '/api/v1/login':
            return self._handle_login()
        if parsed.path == '/api/v1/logout':
            return self._handle_logout()
        return error_response(self, 404, 'NOT_FOUND', 'unknown path')

    def do_PUT(self):
        """处理 PUT 请求"""
        parsed = urlparse(self.path)
        if parsed.path == '/api/v1/config':
            return self._handle_update_config()
        return error_response(self, 404, 'NOT_FOUND', 'unknown path')

    def _handle_update_config(self):
        """处理更新配置请求"""
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length)
        try:
            cfg = json.loads(raw.decode('utf-8'))
        except:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid json')
        
        allowed = {"schema_version", "detection", "alerts", "ui", "security", "smtp"}
        if set(cfg.keys()) - allowed:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'unknown fields')
        
        # 更新本地检测启用状态
        local_detection_enabled = cfg.get('detection', {}).get('local_detection_enabled', True)
        
        try:
            si = cfg['detection']['scan_interval_sec']
            rd = cfg['detection']['retention_days']
            rmax = cfg['detection'].get('retention_max_events', 50000)
            if not (5 <= si <= 3600):
                return error_response(self, 400, 'INVALID_ARGUMENT', 'scan_interval_sec out of range')
            if not (1 <= rd <= 365):
                return error_response(self, 400, 'INVALID_ARGUMENT', 'retention_days out of range')
            if not (1 <= int(rmax) <= 1000000):
                return error_response(self, 400, 'INVALID_ARGUMENT', 'retention_max_events out of range')
            cfg['detection']['retention_max_events'] = int(rmax)
        except:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid detection config')
        
        emails = cfg.get('alerts', {}).get('emails', [])
        if emails:
            import re
            e = emails[0]
            if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', e):
                return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid email')
        
        write_config(cfg)
        return json_response(self, cfg)

    def _read_users(self):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}

    def _write_users(self, users):
        try:
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(users, f)
        except:
            pass

    def _parse_cookies(self):
        raw = self.headers.get('Cookie') or ''
        parts = [p.strip() for p in raw.split(';') if p.strip()]
        m = {}
        for p in parts:
            if '=' in p:
                k, v = p.split('=', 1)
                m[k.strip()] = v.strip()
        return m

    def _is_authenticated(self):
        c = self._parse_cookies()
        token = c.get('session')
        if not token:
            return False
        u = sessions.get(token)
        if not u:
            return False
        if u.get('exp') and u['exp'] < time.time():
            try:
                del sessions[token]
            except:
                pass
            return False
        return True

    def _handle_me(self):
        c = self._parse_cookies()
        token = c.get('session')
        u = sessions.get(token)
        if not u:
            return json_response(self, {"authenticated": False})
        return json_response(self, {"authenticated": True, "username": u.get('username')})

    def _handle_register(self):
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length > 0 else b''
        try:
            payload = json.loads(raw.decode('utf-8')) if raw else {}
        except:
            payload = {}
        username = (payload.get('username') or '').strip()
        password = (payload.get('password') or '')
        email = (payload.get('email') or '').strip()
        if not username or not password or not email:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'missing fields')
        import re
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            return error_response(self, 400, 'INVALID_ARGUMENT', 'invalid email')
        users = self._read_users()
        if username in users and users[username].get('verified'):
            return error_response(self, 400, 'ALREADY_EXISTS', 'user exists')
        import os
        import hashlib
        import random
        salt = os.urandom(8).hex()
        h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        code = f"{random.randint(0,999999):06d}"
        users[username] = {
            "email": email,
            "salt": salt,
            "password_hash": h,
            "verified": False,
            "code": code,
            "code_exp": time.time() + 600
        }
        self._write_users(users)
        from ingest_manager import _send_email
        ok = False
        try:
            ok = _send_email(email, "注册验证码", f"验证码: {code}")
        except:
            ok = False
        return json_response(self, {"sent": bool(ok)})

    def _handle_register_verify(self):
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length > 0 else b''
        try:
            payload = json.loads(raw.decode('utf-8')) if raw else {}
        except:
            payload = {}
        username = (payload.get('username') or '').strip()
        code = (payload.get('code') or '').strip()
        if not username or not code:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'missing fields')
        users = self._read_users()
        u = users.get(username)
        if not u:
            return error_response(self, 404, 'NOT_FOUND', 'user not found')
        if u.get('verified'):
            return json_response(self, {"verified": True})
        if u.get('code') != code:
            return error_response(self, 400, 'INVALID_ARGUMENT', 'code mismatch')
        if u.get('code_exp') and u['code_exp'] < time.time():
            return error_response(self, 400, 'INVALID_ARGUMENT', 'code expired')
        u['verified'] = True
        u['code'] = None
        u['code_exp'] = None
        users[username] = u
        self._write_users(users)
        return json_response(self, {"verified": True})

    def _handle_login(self):
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length > 0 else b''
        try:
            payload = json.loads(raw.decode('utf-8')) if raw else {}
        except:
            payload = {}
        username = (payload.get('username') or '').strip()
        password = (payload.get('password') or '')
        users = self._read_users()
        u = users.get(username)
        if not u or not u.get('verified'):
            return error_response(self, 401, 'UNAUTHORIZED', 'invalid user')
        import hashlib
        h = hashlib.sha256((u.get('salt','') + password).encode('utf-8')).hexdigest()
        if h != u.get('password_hash'):
            return error_response(self, 401, 'UNAUTHORIZED', 'invalid password')
        import os
        token = os.urandom(16).hex()
        sessions[token] = {"username": username, "exp": time.time() + 604800}
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Set-Cookie', f'session={token}; Path=/; HttpOnly; Max-Age=604800')
        self.end_headers()
        self.wfile.write(json.dumps({"logged_in": True}).encode('utf-8'))

    def _handle_logout(self):
        c = self._parse_cookies()
        token = c.get('session')
        if token and token in sessions:
            try:
                del sessions[token]
            except:
                pass
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0')
        self.end_headers()
        self.wfile.write(json.dumps({"logged_out": True}).encode('utf-8'))

def run(host='0.0.0.0', port=8000):
    """启动服务器"""
    ensure_dirs()
    init_alert_state()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    
    # 根据配置决定是否启动本地检测循环
    cfg = read_config()
    local_detection_enabled = cfg.get('detection', {}).get('local_detection_enabled', True)
    if local_detection_enabled:
        threading.Thread(target=ingest_loop, daemon=True).start()
        print("✅ 本地检测循环已启用")
    else:
        print("ℹ️  本地检测循环已禁用（仅接收 Agent 上报）")
    
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"服务器启动在 {host}:{port}")
    print(f"📡 Agent 上报接口: POST http://{host}:{port}/api/v1/ingest")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
