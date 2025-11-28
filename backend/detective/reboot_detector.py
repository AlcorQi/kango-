from .base_detector import BaseDetector
import time
import subprocess

class RebootDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("reboot", config)
        
    def detect(self, line):
        keywords = self.config.get('keywords', [])
        regex_patterns = self.config.get('regex_patterns', [])
        
        if self.detect_line(line, keywords, regex_patterns):
            return {
                'type': 'reboot',
                'severity': 'medium',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'raw_line': line,
                'detection_mode': self.detection_mode
            }
            
        return None
    
    def detect_abnormal_reboot(self):
        """检测异常重启模式"""
        reboot_indicators = []
        
        try:
            # 检查系统启动时间
            uptime_result = subprocess.run(
                ['uptime', '-s'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if uptime_result.returncode == 0:
                boot_time = uptime_result.stdout.strip()
                # 这里可以添加逻辑来比较启动时间，检测频繁重启等模式
                reboot_indicators.append({
                    'type': 'reboot',
                    'severity': 'info',
                    'message': f'系统启动时间: {boot_time}',
                    'timestamp': time.time(),
                    'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'file': 'system_uptime',
                    'line_number': 0,
                    'detection_mode': 'system'
                })
                
        except Exception as e:
            pass
            
        return reboot_indicators