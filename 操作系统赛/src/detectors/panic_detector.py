from .base_detector import BaseDetector
import time

class PanicDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("panic", config)
        
    def detect(self, line):
        if not self.enabled:
            return None
            
        keywords = self.config.get('keywords', [])
        if self.match_keywords(line, keywords):
            return {
                'type': 'panic',
                'severity': 'critical',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        return None
