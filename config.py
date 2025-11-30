import os
import json
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(ROOT, 'web')
DATA_DIR = os.path.join(ROOT, 'data')
CONFIG_DIR = os.path.join(ROOT, 'config')
ANOMALIES_FILE = os.path.join(DATA_DIR, 'anomalies.ndjson')
SUMMARY_FILE = os.path.join(DATA_DIR, 'summary.json')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')

SCHEMA_VERSION = "1.0"

def ensure_dirs():
    """确保必要的目录和文件存在"""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    # 初始化异常数据文件
    if not os.path.exists(ANOMALIES_FILE):
        with open(ANOMALIES_FILE, 'a', encoding='utf-8'):
            pass
    
    # 初始化汇总文件
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
    
    # 初始化配置文件
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                "schema_version": SCHEMA_VERSION,
                "detection": {
                    "log_paths": ["/var/log", "/opt/app/logs"],
                    "scan_interval_sec": 60,
                    "retention_days": 30,
                    "retention_max_events": 50000,
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

def read_config():
    """读取配置文件"""
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_config(cfg):
    """写入配置文件"""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)