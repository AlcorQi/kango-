from .base_detector import BaseDetector
import time

class RebootDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("reboot", config)
        
    def detect(self, line):
        if not self.enabled:
            return None
            
        keywords = self.config.get('keywords', [])
        
        if self.match_keywords(line, keywords):
            return {
                'type': 'reboot',
                'severity': 'medium',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'raw_line': line
            }
            
        return None