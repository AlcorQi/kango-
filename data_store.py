import json
import time
from config import ANOMALIES_FILE, SUMMARY_FILE, SCHEMA_VERSION

def _get_last_scan():
    """获取最后扫描时间，避免循环导入"""
    try:
        from ingest_manager import get_last_scan_ts
        return get_last_scan_ts()
    except:
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

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

def compute_stats(window=None, host_id=None):
    """计算统计信息
    
    :param window: 时间窗口，如 'PT24H' 或 '24h'
    :param host_id: 可选，按主机ID筛选
    """
    total = 0
    by_severity = {"critical": 0, "major": 0, "minor": 0}
    by_type = {}
    by_host = {}
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
        # 按 host_id 筛选
        if host_id and ev.get('host_id') != host_id:
            continue
        
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
        
        h = ev.get('host_id')
        if h:
            by_host[h] = by_host.get(h, 0) + 1
        
        if ev.get('detected_at'):
            if not last_detection or ev['detected_at'] > last_detection:
                last_detection = ev['detected_at']
    
    ls = _get_last_scan()
    return {
        "schema_version": SCHEMA_VERSION,
        "total_anomalies": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "by_host": by_host,
        "trend": [],
        "last_detection": last_detection,
        "last_scan": ls
    }