from .base_detector import BaseDetector
import time
import os

class PanicDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("panic", config)
        
    def detect(self, line):
        keywords = self.config.get('keywords', [])
        regex_patterns = self.config.get('regex_patterns', [])
        
        if self.detect_line(line, keywords, regex_patterns):
            return {
                'type': 'panic',
                'severity': 'critical',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'detection_mode': self.detection_mode
            }
        return None
    
    def detect_crash_dumps(self):
        """检测崩溃转储文件"""
        crash_indicators = []
        
        # 检查常见的崩溃转储目录
        crash_dirs = [
            '/var/crash',
            '/var/log/dump',
            '/var/log/kdump',
            '/var/crash/kernel'
        ]
        
        for crash_dir in crash_dirs:
            if os.path.exists(crash_dir):
                try:
                    for item in os.listdir(crash_dir):
                        if any(item.endswith(ext) for ext in ['.crash', '.dump', '.vmcore']):
                            crash_indicators.append({
                                'type': 'panic',
                'severity': 'critical',
                'message': f'发现内核崩溃转储文件: {os.path.join(crash_dir, item)}',
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'file': 'crash_dump',
                'line_number': 0,
                'detection_mode': 'system'
                            })
                except PermissionError:
                    continue
        
        return crash_indicators