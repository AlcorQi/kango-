import json
import time
from config import ANOMALIES_FILE, SUMMARY_FILE, SCHEMA_VERSION

def read_summary():
    """读取汇总数据"""
    with open(SUMMARY_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_summary(s):
    """写入汇总数据"""
    with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
        json.dump(s, f)

def iter_anomalies():
    """迭代读取所有异常记录"""
    with open(ANOMALIES_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except:
                continue

def parse_iso(s):
    """解析 ISO 8601 时间字符串"""
    try:
        return time.strptime(s, '%Y-%m-%dT%H:%M:%SZ')
    except:
        return None

def compute_stats(window=None):
    """计算统计信息"""
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