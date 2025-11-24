import os
import sys
import time
import yaml
import argparse
from datetime import datetime
import gzip
import subprocess
import shutil
import platform

# 添加项目根目录到 Python 路径，确保可以导入自定义模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入所有检测器
from src.detectors.oom_detector import OOMDetector
from src.detectors.panic_detector import PanicDetector
from src.detectors.reboot_detector import RebootDetector
from src.detectors.oops_detector import OopsDetector
from src.detectors.deadlock_detector import DeadlockDetector
from src.detectors.fs_exception_detector import FSExceptionDetector
import json
import hashlib
import socket

class ExceptionMonitor:
    def __init__(self, config_path=None):
        self.config = self.load_config(config_path)
        self.detectors = []
        self.results = []
        self.start_time = time.time()
        self.setup_detectors()
        print(f"✅ 已启用 {len(self.detectors)} 个检测器")
    
    def load_config(self, config_path):
        """加载配置文件，提供更健壮的默认配置"""
        # 默认配置，包含所有检测器的关键词
        default_config = {
            'log_paths': [
                '/var/log',
                './test.log'
            ],
            'detectors': {
                'oom': {
                    'enabled': True,
                    'keywords': [
                        'Out of memory',
                        'oom-killer',
                        'Killed process',
                        'Memory cgroup out of memory'
                    ]
                },
                'panic': {
                    'enabled': True,
                    'keywords': [
                        'Kernel panic',
                        'kernel panic',
                        'not syncing',
                        'System halted'
                    ]
                },
                'reboot': {
                    'enabled': True,
                    'keywords': [
                        'unexpectedly shut down',
                        'unexpected restart',
                        'system reboot'
                    ]
                },
                # === 新增检测器配置 ===
                'oops': {
                    'enabled': True,
                    'keywords': [
                        'Oops:',
                        'general protection fault',
                        'kernel BUG at',
                        'Unable to handle kernel',
                        'WARNING: CPU:',
                        'BUG: unable to handle kernel',
                        'invalid opcode:',
                        'stack segment:'
                    ]
                },
                'deadlock': {
                    'enabled': True,
                    'keywords': [
                        'possible deadlock',
                        'lock held',
                        'blocked for',
                        'stalled for',
                        'hung task',
                        'task blocked',
                        'soft lockup',
                        'hard lockup'
                    ]
                },
                'fs_exception': {
                    'enabled': True,
                    'keywords': [
                        'filesystem error',
                        'EXT4-fs error',
                        'XFS error',
                        'I/O error',
                        'file system corruption',
                        'superblock corrupt',
                        'metadata corruption',
                        'fsck needed'
                    ]
                }
                # === 新增检测器配置结束 ===
            }
        }

        # 如果配置文件不存在，使用默认配置
        if not config_path or not os.path.exists(config_path):
            print(f"⚠️  警告: 配置文件 {config_path} 不存在，使用默认配置")
            return default_config

        try:
            # 加载用户配置文件
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
            
            # 深度合并配置（默认配置 + 用户配置）
            config = default_config.copy()
            for key in user_config:
                if key in config and isinstance(config[key], dict):
                    config[key].update(user_config[key])
                else:
                    config[key] = user_config[key]
            
            return config
        except Exception as e:
            print(f"❌ 错误: 无法加载配置文件 {config_path}: {e}")
            return default_config
    
    def setup_detectors(self):
        """初始化检测器，增加详细的调试信息和异常处理"""
        detector_configs = self.config.get('detectors', {})
        
        # 检测器映射表，便于动态加载
        detector_classes = {
            'oom': OOMDetector,
            'panic': PanicDetector,
            'reboot': RebootDetector,
            'oops': OopsDetector,
            'deadlock': DeadlockDetector,
            'fs_exception': FSExceptionDetector
        }
        
        print("🔧 正在初始化检测器...")
        
        # 遍历所有检测器类型，动态创建实例
        for detector_name, detector_class in detector_classes.items():
            config = detector_configs.get(detector_name, {})
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
    
    def scan_logs(self):
        """扫描日志文件，增加详细输出和进度信息"""
        print("\n🔍 开始扫描系统日志...")
        total_files = 0
        total_detections = 0

        # 收集所有候选日志文件
        candidate_files = self.collect_log_files()
        
        # 逐个扫描日志文件
        for abs_path in candidate_files:
            print(f"📖 正在读取: {abs_path}")
            detections = self.check_log_file(abs_path)
            total_detections += len(detections)
            total_files += 1

        # 如果支持，扫描 systemd journal
        if self.should_read_journal():
            print("📖 正在读取: systemd journalctl")
            total_detections += self.scan_journal()
        
        # 输出扫描统计
        elapsed_time = time.time() - self.start_time
        print(f"\n📊 扫描完成!")
        print(f"   扫描文件数: {total_files}")
        print(f"   总检测次数: {total_detections}")
        print(f"   耗时: {elapsed_time:.2f}秒")
        
        # 显示详细统计信息
        if total_detections > 0:
            self.show_statistics()
        else:
            print("\nℹ️  未检测到任何异常事件")
            print("可能原因:")
            print("1. 日志文件中确实没有匹配的异常")
            print("2. 检测关键词需要调整")
            print("3. 需要检查日志文件权限")
    
    def check_log_file(self, log_path):
        """检查单个日志文件，增加行数统计和异常处理"""
        detections = []
        line_count = 0
        
        try:
            # 处理压缩日志文件
            if log_path.endswith('.gz'):
                f = gzip.open(log_path, 'rt', errors='ignore')
            else:
                f = open(log_path, 'r', errors='ignore')
                
            with f as fobj:
                for line in fobj:
                    line_count += 1
                    result = self.analyze_line(line)
                    if result:
                        # 添加上下文信息
                        result.update({
                            'file': log_path,
                            'line_number': line_count
                        })
                        detections.append(result)
            
            print(f"   共扫描 {line_count} 行日志，检测到 {len(detections)} 个异常")
            return detections
            
        except PermissionError:
            print(f"❌ 权限不足，无法读取: {log_path}")
            print("💡 尝试使用 sudo 运行:")
            print(f"   sudo python3 {__file__}")
            return []
        except Exception as e:
            print(f"❌ 读取日志文件 {log_path} 出错: {e}")
            return []

    def collect_log_files(self):
        """收集所有需要扫描的日志文件"""
        files = []
        print("📁 正在收集日志文件...")
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(base_dir)
        for p in self.config.get('log_paths', []):
            abs_path = os.path.abspath(p)
            if p.startswith('./') or p.startswith('../'):
                c1 = os.path.abspath(os.path.join(base_dir, p))
                c2 = os.path.abspath(os.path.join(parent_dir, p))
                abs_path = c1 if os.path.exists(c1) else c2
            if os.path.isfile(abs_path):
                files.append(abs_path)
                print(f"   📄 添加文件: {abs_path}")
            elif os.path.isdir(abs_path):
                for root, dirs, filenames in os.walk(abs_path):
                    # 跳过 journal 目录
                    parts = root.replace('\\', '/').split('/')
                    if 'journal' in parts:
                        continue
                    for name in filenames:
                        if self.is_excluded_binary(name):
                            continue
                        if self.is_log_like(name):
                            full_path = os.path.join(root, name)
                            files.append(full_path)
                            print(f"   📄 添加日志文件: {full_path}")
        
        print(f"   📁 总共找到 {len(files)} 个日志文件")
        return files

    def is_log_like(self, name):
        """判断文件名是否像日志文件"""
        lower = name.lower()
        if lower.endswith('.log'):
            return True
        if '.log.' in lower:
            return True
        bases = {
            'syslog', 'messages', 'kern.log', 'dmesg', 'auth.log', 'daemon.log',
            'boot.log', 'cron', 'xorg.log', 'yum.log', 'pacman.log', 'dpkg.log',
            'audit.log'
        }
        return any(lower.startswith(b) for b in bases) or lower.endswith('.gz')

    def is_excluded_binary(self, name):
        """排除二进制日志文件"""
        lower = name.lower()
        excluded = {'lastlog', 'wtmp', 'btmp', 'faillog', 'utmp'}
        for ex in excluded:
            if lower.startswith(ex):
                return True
        return False

    def should_read_journal(self):
        """判断是否应该读取 systemd journal"""
        if platform.system() != 'Linux':
            return False
        if not shutil.which('journalctl'):
            return False
        return True

    def scan_journal(self):
        """扫描 systemd journal"""
        detections = 0
        try:
            # 使用 subprocess 调用 journalctl
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
                result = self.analyze_line(line)
                if result:
                    result.update({'file': 'journalctl', 'line_number': 0})
                    self.results.append(result)
                    detections += 1
                    
            p.wait()
            print(f"   从 journalctl 检测到 {detections} 个异常")
            return detections
            
        except Exception as e:
            print(f"❌ 读取journalctl失败: {e}")
            return 0
    
    def analyze_line(self, line):
        """分析单行日志，增加异常处理确保单个检测器错误不影响整体"""
        for detector in self.detectors:
            try:
                result = detector.detect(line)
                if result:
                    self.handle_detection(result)
                    return result
            except Exception as e:
                # 单个检测器出错不影响其他检测器
                print(f"❌ 检测器 {detector.name} 处理行时出错: {e}")
                print(f"   问题行: {line[:100]}...")
                continue  # 继续执行其他检测器
        return None
    
    def handle_detection(self, result):
        """处理检测结果，优化输出格式"""
        self.results.append(result)
        
        # 根据严重级别选择表情符号
        severity_emoji = {
            'critical': '🔥',
            'high': '🚨',
            'medium': '⚠️',
            'low': 'ℹ️'
        }.get(result.get('severity', 'medium'), '📝')
        
        # 截断过长的消息
        message_preview = result['message'][:100] + '...' if len(result['message']) > 100 else result['message']
        print(f"{severity_emoji} [{result['type'].upper()}] {message_preview}")
        try:
            self.persist_event(result)
        except Exception as e:
            print(f"❌ 数据写入失败: {e}")

    def persist_event(self, result):
        data_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'data'))
        os.makedirs(data_dir, exist_ok=True)
        anomalies = os.path.join(data_dir, 'anomalies.ndjson')
        summary_file = os.path.join(data_dir, 'summary.json')

        detected_at = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        source_file = result.get('file', '')
        line_number = result.get('line_number', 0)
        host_id = socket.gethostname()
        msg = result.get('message', '')
        raw_id = f"{host_id}{source_file}{line_number}{detected_at}{msg}".encode('utf-8')
        eid = hashlib.sha256(raw_id).hexdigest()[:16]
        sev_map = {"critical": "critical", "high": "major", "medium": "minor", "low": "minor"}
        sev = sev_map.get(result.get('severity', 'medium'), 'minor')
        event = {
            "schema_version": "1.0",
            "id": eid,
            "type": result.get('type'),
            "severity": sev,
            "message": msg,
            "source_file": source_file,
            "line_number": line_number,
            "detected_at": detected_at,
            "host_id": host_id,
            "processed": False
        }
        with open(anomalies, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + "\n")
        day_dir = os.path.join(data_dir, 'anomalies')
        os.makedirs(day_dir, exist_ok=True)
        day_file = os.path.join(day_dir, datetime.utcnow().strftime('%Y-%m-%d') + '.ndjson')
        with open(day_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + "\n")
        if os.path.exists(summary_file):
            with open(summary_file, 'r', encoding='utf-8') as f:
                s = json.load(f)
        else:
            s = {
                "schema_version": "1.0",
                "date": datetime.utcnow().strftime('%Y-%m-%d'),
                "total_anomalies": 0,
                "by_severity": {"critical": 0, "major": 0, "minor": 0},
                "by_type": {},
                "hosts": [],
                "trend": []
            }
        s['total_anomalies'] = int(s.get('total_anomalies', 0)) + 1
        bs = s.get('by_severity', {"critical": 0, "major": 0, "minor": 0})
        bs[sev] = int(bs.get(sev, 0)) + 1
        s['by_severity'] = bs
        bt = s.get('by_type', {})
        t = event['type']
        bt[t] = int(bt.get(t, 0)) + 1
        s['by_type'] = bt
        s['last_detection'] = detected_at
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(s, f)
    
    def show_statistics(self):
        """显示统计信息，确保显示所有检测器类型（包括计数为0的）"""
        print("\n📈 检测统计:")
        print("-" * 50)
        
        # 确保显示所有检测器类型，即使计数为0
        stats = {}
        detector_types = [detector.name for detector in self.detectors]
        
        # 统计每个检测器的检测数量
        for detector_type in detector_types:
            count = len([r for r in self.results if r['type'] == detector_type])
            stats[detector_type] = count
        
        # 如果没有检测到任何异常
        if not any(stats.values()):
            print("   未检测到任何异常事件")
            return
        
        # 按检测数量降序排列显示
        for name, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            status = "✅" if count > 0 else "❌"
            print(f"   {status} {name.upper():<12}: {count} 次")
    
    def save_report(self, output_file):
        """保存检测报告，增加更多详细信息"""
        if not self.results:
            print("⚠️  没有检测到异常，不生成报告")
            return

        try:
            # 确保输出目录存在
            directory = os.path.dirname(os.path.abspath(output_file))
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)

            # 写入报告文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("操作系统异常检测报告\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描文件数: {len(self.collect_log_files())}\n")
                f.write(f"检测到异常: {len(self.results)} 个\n")
                f.write("=" * 60 + "\n\n")

                # 按类型分组显示结果
                results_by_type = {}
                for result in self.results:
                    result_type = result['type']
                    if result_type not in results_by_type:
                        results_by_type[result_type] = []
                    results_by_type[result_type].append(result)
                
                # 按类型输出结果
                for result_type, type_results in results_by_type.items():
                    f.write(f"\n【{result_type.upper()} 异常】共 {len(type_results)} 个:\n")
                    f.write("-" * 50 + "\n")
                    
                    for i, result in enumerate(type_results, 1):
                        f.write(f"{i}. 严重性: {result.get('severity', 'UNKNOWN').upper()}\n")
                        f.write(f"   时间: {result.get('formatted_time', '未知')}\n")
                        f.write(f"   来源: {result.get('file', '未知')}:{result.get('line_number', '未知')}\n")
                        f.write(f"   内容: {result['message']}\n")
                        f.write("\n")

            print(f"📄 报告已保存至: {os.path.abspath(output_file)}")
            
        except Exception as e:
            print(f"❌ 保存报告失败: {e}")

def parse_args():
    """解析命令行参数，增加帮助信息"""
    parser = argparse.ArgumentParser(
        description='操作系统异常信息检测工具',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('-c', '--config',
                       default='config/default.yaml',
                       help='指定配置文件路径')
    
    parser.add_argument('-o', '--output',
                       default='report.txt',
                       help='指定输出报告文件路径')
    
    return parser.parse_args()

def main():
    """主程序入口，增加欢迎信息"""
    print("=" * 60)
    print("🖥️  操作系统异常信息检测工具 v1.0")
    print("=" * 60)
    
    # 解析命令行参数
    args = parse_args()
    
    # 创建监控实例并执行扫描
    monitor = ExceptionMonitor(args.config)
    monitor.scan_logs()
    
    # 保存报告
    monitor.save_report(args.output)
    
    print("\n🎉 程序执行完成!")

if __name__ == "__main__":
    main()
