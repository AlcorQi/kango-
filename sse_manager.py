import json
import time
import os
import threading
from config import ANOMALIES_FILE

clients_lock = threading.Lock()
clients = set()
tailer_started = False
heartbeat_started = False

def publish_event(ev):
    """发布事件给所有 SSE 客户端"""
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
    """心跳循环，保持 SSE 连接活跃"""
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
    """文件追踪循环，实时检测新异常"""
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

def add_client(client):
    """添加 SSE 客户端"""
    with clients_lock:
        clients.add(client)

def remove_client(client):
    """移除 SSE 客户端"""
    with clients_lock:
        try:
            clients.remove(client)
        except:
            pass