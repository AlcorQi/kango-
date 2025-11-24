from .base_detector import BaseDetector
import time

class FSExceptionDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("fs_exception", config)

    def detect(self, line):
        if not self.enabled:
            return None
        keywords = self.config.get('keywords', [])
        if self.match_keywords(line, keywords):
            return {
                'type': 'fs_error',
                'severity': 'major',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        return None
