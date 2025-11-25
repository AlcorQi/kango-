import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, result_manager, file_scanner):
        self.result_manager = result_manager
        self.file_scanner = file_scanner
    
    def save_report(self, output_file, results):
        """保存检测报告"""
        if not results:
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
                f.write(f"扫描文件数: {len(self.file_scanner.collect_log_files())}\n")
                f.write(f"检测到异常: {len(results)} 个\n")
                f.write("=" * 60 + "\n\n")

                # 按类型分组显示结果
                results_by_type = {}
                for result in results:
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