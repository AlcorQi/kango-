import sys
import os
import subprocess
import time

# 添加项目根目录到 Python 路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detectors.oom_detector import OOMDetector
from src.detectors.panic_detector import PanicDetector
from src.detectors.reboot_detector import RebootDetector
from src.detectors.oops_detector import OopsDetector
from src.detectors.deadlock_detector import DeadlockDetector
from src.detectors.fs_exception_detector import FSExceptionDetector

class DetectorManager:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.detectors = []
        self.setup_detectors()
    
    def setup_detectors(self):
        """初始化检测器"""
        detector_classes = {
            'oom': OOMDetector,
            'panic': PanicDetector,
            'reboot': RebootDetector,
            'oops': OopsDetector,
            'deadlock': DeadlockDetector,
            'fs_exception': FSExceptionDetector
        }
        
        print("🔧 正在初始化检测器...")
        
        for detector_name, detector_class in detector_classes.items():
            config = self.config_manager.get_detector_config(detector_name)
            if config.get('enabled', False):
                try:
                    detector = detector_class(config)
                    self.detectors.append(detector)
                    keyword_count = len(config.get('keywords', []))
                    print(f"   ✅ {detector_name.upper()}检测器已加载 ({keyword_count}个关键词)")
                except Exception as e:
                    print(f"   ❌ {detector_name.upper()}检测器加载失败: {e}")
            else:
                print(f"   ⚠️  {detector_name.upper()}检测器已禁用")
    
    def analyze_line(self, line):
        """分析单行日志"""
        for detector in self.detectors:
            try:
                result = detector.detect(line)
                if result:
                    return result
            except Exception as e:
                print(f"❌ 检测器 {detector.name} 处理行时出错: {e}")
                print(f"   问题行: {line[:100]}...")
                continue
        return None
    
    def get_detector_names(self):
        """获取所有检测器名称"""
        return [detector.name for detector in self.detectors]
    
    def detect_system_issues(self):
        """检测系统级别的问题（死锁、panic状态等）"""
        issues = []
        
        # 检测死锁状态
        deadlock_issues = self.detect_deadlock_state()
        issues.extend(deadlock_issues)
        
        # 检测panic和崩溃转储
        panic_issues = self.detect_panic_state()
        issues.extend(panic_issues)
        
        return issues
    
    def detect_deadlock_state(self):
        """使用SysRq检测死锁状态"""
        issues = []
        try:
            # 检查SysRq是否启用
            if os.path.exists('/proc/sys/kernel/sysrq'):
                with open('/proc/sys/kernel/sysrq', 'r') as f:
                    sysrq_enabled = int(f.read().strip()) > 0
            else:
                sysrq_enabled = False
            
            if not sysrq_enabled:
                print("⚠️  SysRq未启用，无法进行精确死锁检测")
                # 即使SysRq未启用，仍然尝试基本的死锁检测
                return self.detect_basic_deadlock()
            
            # 触发SysRq显示阻塞任务
            result = subprocess.run(
                ['echo', 'w'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 检查D状态（不可中断睡眠）的任务
            ps_result = subprocess.run(
                ['ps', 'aux'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 分析进程状态
            for line in ps_result.stdout.split('\n'):
                if ' D ' in line and not ('kworker' in line or 'ksoftirqd' in line):
                    parts = line.split()
                    if len(parts) > 10:
                        pid = parts[1]
                        cmd = ' '.join(parts[10:])
                        
                        # 获取进程的堆栈信息
                        try:
                            stack_path = f'/proc/{pid}/stack'
                            if os.path.exists(stack_path):
                                with open(stack_path, 'r') as stack_file:
                                    stack_trace = stack_file.read()
                                
                                if 'mutex_lock' in stack_trace or 'semaphore' in stack_trace:
                                    issues.append({
                                        'type': 'deadlock',
                                        'severity': 'critical',
                                        'message': f'检测到可能的死锁: PID {pid} ({cmd}) 处于D状态，等待锁',
                                        'timestamp': time.time(),
                                        'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                                        'file': 'system_state',
                                        'line_number': 0
                                    })
                        except (PermissionError, FileNotFoundError):
                            pass
                            
        except Exception as e:
            print(f"⚠️  死锁状态检测失败: {e}")
        
        return issues
    
    def detect_basic_deadlock(self):
        """基本的死锁检测（不依赖SysRq）"""
        issues = []
        try:
            # 使用ps检查D状态进程
            ps_result = subprocess.run(
                ['ps', 'aux'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            d_state_count = 0
            for line in ps_result.stdout.split('\n'):
                if ' D ' in line and not ('kworker' in line or 'ksoftirqd' in line):
                    d_state_count += 1
            
            if d_state_count > 2:  # 如果有多个非内核进程处于D状态，可能是死锁
                issues.append({
                    'type': 'deadlock',
                    'severity': 'high',
                    'message': f'检测到 {d_state_count} 个进程处于D状态(不可中断睡眠)，可能存在死锁',
                    'timestamp': time.time(),
                    'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'file': 'process_state',
                    'line_number': 0
                })
                
        except Exception as e:
            print(f"⚠️  基本死锁检测失败: {e}")
        
        return issues
    
    def detect_panic_state(self):
        """检测系统panic状态和崩溃转储"""
        issues = []
        try:
            # 检查崩溃转储目录
            crash_dirs = ['/var/crash', '/var/log/dump', '/var/log/kdump']
            for crash_dir in crash_dirs:
                if os.path.exists(crash_dir):
                    try:
                        for item in os.listdir(crash_dir):
                            if any(item.endswith(ext) for ext in ['.crash', '.dump', '.vmcore']):
                                issues.append({
                                    'type': 'panic',
                                    'severity': 'critical',
                                    'message': f'发现系统崩溃转储文件: {os.path.join(crash_dir, item)}',
                                    'timestamp': time.time(),
                                    'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                                    'file': 'crash_dump',
                                    'line_number': 0
                                })
                    except (PermissionError, FileNotFoundError):
                        continue
            
            # 检查kexec状态
            kexec_path = '/sys/kernel/kexec_crash_loaded'
            if os.path.exists(kexec_path):
                try:
                    with open(kexec_path, 'r') as f:
                        if f.read().strip() == '1':
                            issues.append({
                                'type': 'panic',
                                'severity': 'high',
                                'message': '系统已配置崩溃转储(kexec)，可能发生过内核恐慌',
                                'timestamp': time.time(),
                                'formatted_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                                'file': 'kexec_status',
                                'line_number': 0
                            })
                except (PermissionError, IOError):
                    pass
                    
        except Exception as e:
            print(f"⚠️  Panic状态检测失败: {e}")
        
        return issues