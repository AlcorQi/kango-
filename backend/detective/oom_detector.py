from .base_detector import BaseDetector
import time

class OOMDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("oom", config)
        
    def detect(self, line):
        keywords = self.config.get('keywords', [])
        regex_patterns = self.config.get('regex_patterns', [])
        
        if self.detect_line(line, keywords, regex_patterns):
            return {
                'type': 'oom',
                'severity': 'high',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'detection_mode': self.detection_mode  # 记录检测模式
            }
        return None