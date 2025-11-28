from abc import ABC, abstractmethod
import re

class BaseDetector(ABC):
    def __init__(self, name, config):
        self.name = name
        self.config = config
        self.enabled = config.get('enabled', True)
        self.detection_mode = config.get('detection_mode', 'keyword')  # keyword, regex, mixed
    
    @abstractmethod
    def detect(self, line):
        pass
        
    def match_keywords(self, line, keywords):
        """纯关键字匹配"""
        for keyword in keywords:
            if keyword.lower() in line.lower():
                return True
        return False
        
    def match_regex(self, line, patterns):
        """纯正则表达式匹配"""
        for pattern in patterns:
            try:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
            except re.error:
                print(f"⚠️  正则表达式错误: {pattern}")
                continue
        return False
    
    def match_mixed(self, line, keywords, patterns):
        """混合模式匹配 - 关键字或正则表达式"""
        # 先检查关键字
        if keywords and self.match_keywords(line, keywords):
            return True
        
        # 再检查正则表达式
        if patterns and self.match_regex(line, patterns):
            return True
            
        return False
    
    def detect_line(self, line, keywords, regex_patterns=None):
        """
        统一的检测方法，根据模式选择检测策略
        """
        if not self.enabled:
            return None
            
        regex_patterns = regex_patterns or []
        
        if self.detection_mode == 'keyword':
            if self.match_keywords(line, keywords):
                return True
                
        elif self.detection_mode == 'regex':
            if regex_patterns and self.match_regex(line, regex_patterns):
                return True
                
        elif self.detection_mode == 'mixed':
            if self.match_mixed(line, keywords, regex_patterns):
                return True
                
        return False