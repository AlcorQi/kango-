from abc import ABC, abstractmethod
import re

class BaseDetector(ABC):
    def __init__(self, name, config):
        self.name = name
        self.config = config
        self.enabled = config.get('enabled', True)
    
    @abstractmethod
    def detect(self, line):
        pass
        
    def match_keywords(self, line, keywords):
        for keyword in keywords:
            if keyword.lower() in line.lower():
                return True
        return False
        
    def match_regex(self, line, patterns):
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
