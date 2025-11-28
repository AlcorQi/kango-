from .base_detector import BaseDetector
import time
import subprocess
import os

class DeadlockDetector(BaseDetector):
    def __init__(self, config):
        super().__init__("deadlock", config)

    def detect(self, line):
        keywords = self.config.get('keywords', [])
        regex_patterns = self.config.get('regex_patterns', [])
        
        if self.detect_line(line, keywords, regex_patterns):
            return {
                'type': 'deadlock',
                'severity': 'major',
                'message': line.strip(),
                'timestamp': time.time(),
                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'detection_mode': self.detection_mode
            }
        return None
    
    def detect_sysrq_deadlock(self):
        """使用SysRq检测死锁状态"""
        deadlock_indicators = []
        
        try:
            # 检查D状态进程（不可中断睡眠）
            ps_result = subprocess.run(
                ['ps', 'aux'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            d_state_processes = []
            for line in ps_result.stdout.split('\n'):
                if ' D ' in line:
                    # 排除内核工作线程
                    if not any(kernel_proc in line for kernel_proc in ['kworker', 'ksoftirqd']):
                        d_state_processes.append(line.strip())
            
            if d_state_processes:
                for proc_info in d_state_processes[:5]:  # 限制数量避免过多输出
                    deadlock_indicators.append({
                        'type': 'deadlock',
                        'severity': 'critical',
                        'message': f'进程处于D状态(可能死锁): {proc_info}',
                        'timestamp': time.time(),
                        'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'file': 'process_state',
                        'line_number': 0,
                        'detection_mode': 'system'
                    })
                    
        except Exception as e:
            # 忽略权限错误等
            pass
            
        return deadlock_indicators