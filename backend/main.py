import os
import sys
import time
import argparse

# 添加项目根目录到 Python 路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_config.config_master import ConfigManager

from detective.detector_ctrl import DetectorManager

from log.file_scanner import FileScanner
from log.journal_scanner import JournalScanner

from result_manager import ResultManager

from report.report_generator import ReportGenerator

class ExceptionMonitor:
    def __init__(self, config_path=None):
        self.config_manager = ConfigManager(config_path)
        self.file_scanner = FileScanner(self.config_manager)
        self.detector_manager = DetectorManager(self.config_manager)
        self.result_manager = ResultManager()
        self.journal_scanner = JournalScanner(self.detector_manager, self.result_manager)
        self.report_generator = ReportGenerator(self.result_manager, self.file_scanner)
        
        print(f"✅ 已启用 {len(self.detector_manager.detectors)} 个检测器")
    
    def scan_logs(self):
        """扫描日志文件"""
        print("\n🔍 开始扫描系统日志...")
        self.result_manager.start_timer()
        total_files = 0
        total_detections = 0

        # 首先检测系统级别问题（死锁、panic状态等）
        print("🔍 正在检测系统状态问题...")
        system_issues = self.detector_manager.detect_system_issues()
        for issue in system_issues:
            self.result_manager.add_result(issue)
        total_detections += len(system_issues)
        print(f"   检测到 {len(system_issues)} 个系统状态问题")

        # 收集所有候选日志文件
        candidate_files = self.file_scanner.collect_log_files()
        
        # 逐个扫描日志文件
        for abs_path in candidate_files:
            print(f"📖 正在读取: {abs_path}")
            detections = self.check_log_file(abs_path)
            total_detections += len(detections)
            total_files += 1

        # 如果支持，扫描 systemd journal
        if self.file_scanner.should_read_journal():
            print("📖 正在读取: systemd journalctl")
            total_detections += self.journal_scanner.scan_journal()
        
        # 输出扫描统计
        elapsed_time = self.result_manager.get_elapsed_time()
        print(f"\n📊 扫描完成!")
        print(f"   扫描文件数: {total_files}")
        print(f"   总检测次数: {total_detections}")
        print(f"   耗时: {elapsed_time:.2f}秒")
        
        # 显示详细统计信息
        if total_detections > 0:
            self.result_manager.show_statistics(self.detector_manager.get_detector_names())
        else:
            print("\nℹ️  未检测到任何异常事件")
            print("可能原因:")
            print("1. 日志文件中确实没有匹配的异常")
            print("2. 检测关键词需要调整")
            print("3. 需要检查日志文件权限")
    
    def check_log_file(self, log_path):
        """检查单个日志文件"""
        detections = []
        lines, line_count = self.file_scanner.read_log_file(log_path)
        
        for line_number, line in enumerate(lines, 1):
            result = self.detector_manager.analyze_line(line)
            if result:
                # 添加上下文信息
                result.update({
                    'file': log_path,
                    'line_number': line_number
                })
                self.result_manager.add_result(result)
                detections.append(result)
        
        print(f"   共扫描 {line_count} 行日志，检测到 {len(detections)} 个异常")
        return detections
    
    def save_report(self, output_file):
        """保存检测报告"""
        self.report_generator.save_report(output_file, self.result_manager.results)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='操作系统异常信息检测工具',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('-c', '--config',
                       default='./backend/anomaly_config/default.yaml',
                       help='指定配置文件路径')
    
    parser.add_argument('-o', '--output',
                       default='./backend/report/report.txt',
                       help='指定输出报告文件路径')
    
    parser.add_argument('--sysrq-check', action='store_true',
                       help='启用SysRq死锁检测（需要root权限）')
    
    return parser.parse_args()

def main():
    """主程序入口"""
    print("=" * 60)
    print("🖥️  操作系统异常信息检测工具 v2.0")
    print("增强特性: 系统状态检测(SysRq死锁、崩溃转储分析、oops误报修复)")
    print("=" * 60)
    
    # 解析命令行参数
    args = parse_args()
    
    # 创建监控实例并执行扫描
    monitor = ExceptionMonitor(args.config)
    monitor.scan_logs()
    
    # 保存报告
    monitor.save_report(args.output)
    
    print("\n🎉 程序执行完成!")
    if args.sysrq_check:
        print("💡 提示: 使用 --sysrq-check 参数需要root权限以获得更精确的死锁检测")

if __name__ == "__main__":
    main()