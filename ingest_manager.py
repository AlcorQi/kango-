import os
import json
import time
import socket
import hashlib
import smtplib
import threading
import re
from email.message import EmailMessage
from config import DATA_DIR, CONFIG_FILE, ANOMALIES_FILE, SCHEMA_VERSION, read_config

OFFSETS_FILE = os.path.join(DATA_DIR, 'ingest_offsets.json')
ALERT_STATE_FILE = os.path.join(DATA_DIR, 'alert_state.json')

ingest_started = False
cleanup_started = False
last_scan_ts = None
alert_state = {}

# 基于 backend/调试命令格式（模式选择）.md 的正则模式（做了简化）
REGEX_PATTERNS = {
    "oom": [
        r"(?:Out\s+of\s+memory|OOM).*?(?:kill|terminat).*?process.*?\d+",
        r"oom.*?killer.*?invoked.*?(?:gfp_mask|order)=\w+",
    ],
    "kernel_panic": [
        r"(?:Kernel|kernel).*?panic.*?(?:not\s+syncing|System\s+halted)",
        r"(?:Unable\s+to\s+mount|Cannot\s+mount).*?root.*?(?:filesystem|device)",
    ],
    "unexpected_reboot": [
        r"(?:unexpected|unclean).*?(?:shut.*?down|restart|reboot)",
        r"system.*?(?:reboot|restart).*?(?:initiated|triggered)",
    ],
    "fs_error": [
        r"(?:filesystem|file\s+system).*?error.*?(?:corrupt|damage)",
        r"(?:EXT4|XFS).*?(?:error|corruption).*?detected",
    ],
    "oops": [
        r"OOPS?:.*?(?:general protection|GPF)",
        r"(?:kernel|Kernel).*?BUG.*?at.*?\.(?:c|h):\d+",
    ],
    "deadlock": [
        r"(?:possible|potential).*?deadlock.*?(?:detected|found)",
        r"INFO.*?task.*?blocked.*?more.*?\d+.*?seconds",
    ],
}

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
    cfg = {}
    try:
        cfg = read_config()
    except:
        cfg = {}
    smtp = cfg.get('smtp', {})
    host = smtp.get('host') or os.environ.get('SMTP_HOST')
    port_raw = smtp.get('port') or os.environ.get('SMTP_PORT') or '25'
    try:
        port = int(port_raw)
    except:
        port = 25
    user = smtp.get('user') or os.environ.get('SMTP_USER')
    pwd = smtp.get('pass') or os.environ.get('SMTP_PASS')
    sender = (smtp.get('from') or os.environ.get('SMTP_FROM') or (user or 'noreply@example.com'))
    tls_cfg = smtp.get('tls')
    tls = (str(tls_cfg).lower() in ('1','true','yes')) if tls_cfg is not None else (os.environ.get('SMTP_TLS') == '1')
    if not host or not to_addr:
        try:
            print(f"[ALERT] 邮件发送未执行: SMTP_HOST={bool(host)} 收件人={bool(to_addr)} 配置来源={'config' if smtp.get('host') else 'env'}")
        except:
            pass
        return False
    try:
        msg = EmailMessage()
        msg['From'] = sender
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            if tls:
                smtp.starttls()
            if user and pwd:
                smtp.login(user, pwd)
            smtp.send_message(msg)
        return True
    except Exception as e:
        try:
            print(f"[ALERT] 邮件发送失败: {e}")
        except:
            pass
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

def _match_types(line, enabled, mode: str):
    """匹配异常类型

    :param line: 日志原始行
    :param enabled: 已启用的检测类型列表
    :param mode: 搜索 / 检测模式：keyword / regex / mixed
    """
    s = line.lower()
    types = []

    use_keyword = mode in ("keyword", "mixed", None)
    use_regex = mode in ("regex", "mixed")

    # 关键字模式：简单 contains 匹配，性能最好
    if use_keyword:
        if "oom" in enabled:
            if ("out of memory" in s) or ("oom-killer" in s) or ("oom killer" in s):
                types.append("oom")
        if "kernel_panic" in enabled:
            if "kernel panic" in s or "kernel panic - not syncing" in s:
                types.append("kernel_panic")
        if "unexpected_reboot" in enabled:
            if ("reboot" in s) or ("booting" in s):
                types.append("unexpected_reboot")
        if "fs_error" in enabled:
            if (
                ("fs error" in s)
                or ("i/o error" in s)
                or ("filesystem corruption" in s)
                or ("ext4-fs error" in s)
                or ("xfs error" in s)
            ):
                types.append("fs_error")
        if "oops" in enabled:
            if "oops:" in s or "kernel bug" in s:
                types.append("oops")
        if "deadlock" in enabled:
            if ("deadlock" in s) or ("recursive locking" in s) or ("hung task" in s):
                types.append("deadlock")

    # 正则模式：使用更复杂的模式匹配，精度更高
    if use_regex:
        for t in enabled:
            if t in REGEX_PATTERNS and t not in types:
                for pat in REGEX_PATTERNS[t]:
                    try:
                        if re.search(pat, line, re.IGNORECASE):
                            types.append(t)
                            break
                    except re.error:
                        # 正则错误时跳过该模式
                        continue

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
    """日志摄取循环（本地检测模式）
    
    注意：如果配置中 local_detection_enabled 为 False，此循环不会启动。
    此时系统仅接收 Agent 上报的数据。
    """
    global ingest_started, last_scan_ts
    if ingest_started:
        return
    ingest_started = True
    offsets = _load_offsets()
    # 初始化最后扫描时间
    last_scan_ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    
    while True:
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except:
            cfg = {}
        det = cfg.get('detection', {})
        
        # 检查是否启用本地检测
        local_detection_enabled = det.get('local_detection_enabled', True)
        if not local_detection_enabled:
            # 如果禁用本地检测，等待一段时间后重新检查配置
            time.sleep(60)
            continue
        
        interval = int(det.get('scan_interval_sec', 60))
        paths = det.get('log_paths', [])
        enabled = det.get('enabled_detectors', [])
        # 从 config/config.json 中读取搜索 / 检测模式，默认 mixed
        search_mode = det.get('search_mode', 'mixed')
        files = _collect_paths(paths)
        # 在每次扫描开始时更新最后扫描时间
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
                        types = _match_types(line, enabled, search_mode)
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
        try:
            rmax_now = int(det.get('retention_max_events', 0))
            if rmax_now:
                try:
                    with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
                        total_lines = sum(1 for _ in f)
                except:
                    total_lines = 0
                if total_lines > rmax_now:
                    try:
                        cleanup_once(cfg, "超过保留上限")
                    except:
                        pass
        except:
            pass
        try:
            start = max(5, min(3600, int(interval)))
        except:
            start = 60
        waited = 0
        while waited < start:
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    cfg2 = json.load(f)
            except:
                cfg2 = {}
            det2 = cfg2.get('detection', {})
            try:
                cur_interval = int(det2.get('scan_interval_sec', start))
            except:
                cur_interval = start
            
            cur_paths = det2.get('log_paths', [])
            cur_enabled = det2.get('enabled_detectors', [])

            # 如果间隔、路径或启用的检测器发生变化，立即中断等待
            if cur_interval != start or cur_paths != paths or cur_enabled != enabled:
                break
            
            time.sleep(1)
            waited += 1

def cleanup_loop():
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
        ui = cfg.get('ui', {})
        rd = int(det.get('retention_days', 30))
        rmax = int(det.get('retention_max_events', 50000))
        cutoff = time.time() - rd * 86400
        try:
            print(f"[CLEANUP] 开始执行清理: 保留天数={rd}, 保留上限={rmax}")
        except:
            pass
        try:
            events = []
            total_before = 0
            with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    total_before += 1
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
                        events.append((te or 0, s))
            events.sort(key=lambda x: x[0])
            if rmax and len(events) > rmax:
                events = events[-rmax:]
            try:
                with open(ANOMALIES_FILE, 'r+', encoding='utf-8') as f:
                    f.seek(0)
                    for _, s in events:
                        f.write(s + "\n")
                    f.truncate()
                try:
                    total_after = len(events)
                    removed = max(0, total_before - total_after)
                    print(f"[CLEANUP] 事件保留: 原={total_before}, 新={total_after}, 删除={removed}")
                except:
                    pass
            except:
                pass
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
            try:
                print("[CLEANUP] 日归档清理完成")
            except:
                pass
        except:
            pass
        try:
            offsets = _load_offsets()
            changed = False
            removed_cnt = 0
            for fp in list(offsets.keys()):
                try:
                    if not os.path.exists(fp):
                        del offsets[fp]
                        changed = True
                        removed_cnt += 1
                except:
                    continue
            if changed:
                _save_offsets(offsets)
                try:
                    print(f"[CLEANUP] 偏移表清理: 移除={removed_cnt}")
                except:
                    pass
        except:
            pass
        try:
            print("[CLEANUP] 下次清理将在 1800s 后执行")
        except:
            pass
        time.sleep(1800)

def cleanup_once(cfg, reason=None):
    det = cfg.get('detection', {})
    rd = int(det.get('retention_days', 30))
    rmax = int(det.get('retention_max_events', 50000))
    cutoff = time.time() - rd * 86400
    try:
        if reason:
            print(f"[CLEANUP] 触发清理: {reason}")
    except:
        pass
    try:
        events = []
        total_before = 0
        with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                total_before += 1
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
                    events.append((te or 0, s))
        events.sort(key=lambda x: x[0])
        if rmax and len(events) > rmax:
            events = events[-rmax:]
        try:
            with open(ANOMALIES_FILE, 'r+', encoding='utf-8') as f:
                f.seek(0)
                for _, s in events:
                    f.write(s + "\n")
                f.truncate()
            try:
                total_after = len(events)
                removed = max(0, total_before - total_after)
                print(f"[CLEANUP] 事件保留: 原={total_before}, 新={total_after}, 删除={removed}")
            except:
                pass
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
        try:
            offsets = _load_offsets()
            changed = False
            removed_cnt = 0
            for fp in list(offsets.keys()):
                try:
                    if not os.path.exists(fp):
                        del offsets[fp]
                        changed = True
                        removed_cnt += 1
                except:
                    continue
            if changed:
                _save_offsets(offsets)
                try:
                    print(f"[CLEANUP] 偏移表清理: 移除={removed_cnt}")
                except:
                    pass
        except:
            pass
    except:
        pass

def init_alert_state():
    """初始化告警状态"""
    global alert_state
    alert_state = _load_alert_state()

def get_last_scan_ts():
    """获取最后扫描时间戳"""
    global last_scan_ts
    if last_scan_ts:
        return last_scan_ts
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
