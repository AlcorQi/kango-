import subprocess

class JournalScanner:
    def __init__(self, detector_manager, result_manager):
        self.detector_manager = detector_manager
        self.result_manager = result_manager
    
    def scan_journal(self):
        """扫描 systemd journal"""
        detections = 0
        try:
            p = subprocess.Popen(
                ['journalctl', '-o', 'short-iso', '--no-pager'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            # 逐行处理 journal 输出
            for line in p.stdout:
                result = self.detector_manager.analyze_line(line)
                if result:
                    result.update({'file': 'journalctl', 'line_number': 0})
                    self.result_manager.add_result(result)
                    detections += 1
                    
            p.wait()
            print(f"   从 journalctl 检测到 {detections} 个异常")
            return detections
            
        except Exception as e:
            print(f"❌ 读取journalctl失败: {e}")
            return 0