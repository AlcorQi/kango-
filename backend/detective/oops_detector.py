from .base_detector import BaseDetector
import time

class OopsDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("oops", config)
        # 误报排除列表 - 这些内容不应该被识别为OOPS异常
        self.false_positive_patterns = [
            'install kerneloops',
            'status half-installed kerneloops',
            'status unpacked kerneloops', 
            'configure kerneloops',
            'status installed kerneloops',
            'Install: kerneloops:amd64',
            'kerneloops:amd64'
        ]

    def detect(self, line):
        if not self.enabled:
            return None
        
        # 先检查是否是误报
        if self.is_false_positive(line):
            return None
            
        keywords = self.config.get('keywords', [])
        if self.match_keywords(line, keywords):
            return {
                'type': 'oops',
                'severity': 'major',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        return None
    
    def is_false_positive(self, line):
        """检查是否是误报（软件包管理操作等）"""
        line_lower = line.lower()
        
        # 检查是否是软件包管理相关的误报
        for pattern in self.false_positive_patterns:
            if pattern in line_lower:
                return True
        
        # 检查是否在软件包管理日志中且包含"kerneloops"关键词
        if any(keyword in line_lower for keyword in ['kerneloops', 'kerneloops']):
            # 如果是软件包安装、配置等操作，视为误报
            package_operations = ['install', 'remove', 'purge', 'configure', 'status']
            if any(op in line_lower for op in package_operations):
                return True
        
        return False