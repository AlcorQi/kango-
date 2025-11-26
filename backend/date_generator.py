import json
import hashlib
import socket
import os
from datetime import datetime

class ResultManager:
    def __init__(self):
        self.results = []
        self.start_time = None
    
    def start_timer(self):
        """开始计时"""
        import time
        self.start_time = time.time()
    
    def get_elapsed_time(self):
        """获取经过的时间"""
        import time
        if self.start_time:
            return time.time() - self.start_time
        return 0
    
    def add_result(self, result):
        """添加检测结果"""
        self.results.append(result)
        self.handle_detection(result)
    
    def handle_detection(self, result):
        """处理检测结果"""
        # 根据严重级别选择表情符号
        severity_emoji = {
            'critical': '🔥',
            'high': '🚨',
            'medium': '⚠️',
            'low': 'ℹ️'
        }.get(result.get('severity', 'medium'), '📝')
        
        # 截断过长的消息
        message_preview = result['message'][:100] + '...' if len(result['message']) > 100 else result['message']
        print(f"{severity_emoji} [{result['type'].upper()}] {message_preview}")
        
        # 持久化存储
        try:
            self.persist_event(result)
        except Exception as e:
            print(f"❌ 数据写入失败: {e}")
    
    def persist_event(self, result):
        """持久化存储事件"""
        data_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data'))
        os.makedirs(data_dir, exist_ok=True)
        anomalies = os.path.join(data_dir, 'anomalies.ndjson')
        summary_file = os.path.join(data_dir, 'summary.json')

        detected_at = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        source_file = result.get('file', '')
        line_number = result.get('line_number', 0)
        host_id = socket.gethostname()
        msg = result.get('message', '')
        raw_id = f"{host_id}{source_file}{line_number}{detected_at}{msg}".encode('utf-8')
        eid = hashlib.sha256(raw_id).hexdigest()[:16]
        sev_map = {"critical": "critical", "high": "major", "medium": "minor", "low": "minor"}
        sev = sev_map.get(result.get('severity', 'medium'), 'minor')
        
        event = {
            "schema_version": "1.0",
            "id": eid,
            "type": result.get('type'),
            "severity": sev,
            "message": msg,
            "source_file": source_file,
            "line_number": line_number,
            "detected_at": detected_at,
            "host_id": host_id,
            "processed": False
        }
        
        # 写入主异常文件
        with open(anomalies, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + "\n")
        
        # 按日期存储
        day_dir = os.path.join(data_dir, 'anomalies')
        os.makedirs(day_dir, exist_ok=True)
        day_file = os.path.join(day_dir, datetime.utcnow().strftime('%Y-%m-%d') + '.ndjson')
        with open(day_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + "\n")
        
        # 更新摘要文件
        self.update_summary(summary_file, event, detected_at, sev)
    
    def update_summary(self, summary_file, event, detected_at, severity):
        """更新摘要文件"""
        if os.path.exists(summary_file):
            with open(summary_file, 'r', encoding='utf-8') as f:
                s = json.load(f)
        else:
            s = {
                "schema_version": "1.0",
                "date": datetime.utcnow().strftime('%Y-%m-%d'),
                "total_anomalies": 0,
                "by_severity": {"critical": 0, "major": 0, "minor": 0},
                "by_type": {},
                "hosts": [],
                "trend": []
            }
        
        s['total_anomalies'] = int(s.get('total_anomalies', 0)) + 1
        bs = s.get('by_severity', {"critical": 0, "major": 0, "minor": 0})
        bs[severity] = int(bs.get(severity, 0)) + 1
        s['by_severity'] = bs
        bt = s.get('by_type', {})
        t = event['type']
        bt[t] = int(bt.get(t, 0)) + 1
        s['by_type'] = bt
        s['last_detection'] = detected_at
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(s, f)
    
    def get_statistics(self, detector_names):
        """获取统计信息"""
        stats = {}
        for detector_type in detector_names:
            count = len([r for r in self.results if r['type'] == detector_type])
            stats[detector_type] = count
        return stats
    
    def show_statistics(self, detector_names):
        """显示统计信息"""
        print("\n📈 检测统计:")
        print("-" * 50)
        
        stats = self.get_statistics(detector_names)
        
        # 如果没有检测到任何异常
        if not any(stats.values()):
            print("   未检测到任何异常事件")
            return
        
        # 按检测数量降序排列显示
        for name, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            status = "✅" if count > 0 else "❌"
            print(f"   {status} {name.upper():<12}: {count} 次")