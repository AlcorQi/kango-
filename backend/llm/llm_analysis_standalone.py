import argparse
import os
import sys

# 添加项目根目录到 Python 路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm.llm_analyzer import LLMAnalyzer

def main():
    """独立运行LLM分析"""
    parser = argparse.ArgumentParser(description='操作系统异常大语言模型分析工具')
    parser.add_argument('-d', '--data-dir', default='./data', help='数据目录路径')
    parser.add_argument('-o', '--output', default='./backend/report/llm_analysis.txt', 
                       help='输出报告文件路径')
    args = parser.parse_args()
    
    print("=" * 60)
    print("🤖 操作系统异常大语言模型分析")
    print("=" * 60)
    
    # 创建分析器并执行分析
    analyzer = LLMAnalyzer()
    print("📊 正在分析异常数据...")
    analysis_result = analyzer.analyze_system_anomalies(args.data_dir)
    
    # 保存分析结果
    if analyzer.save_analysis_report(args.output, analysis_result):
        print("✅ 分析完成!")
    else:
        print("❌ 分析完成但保存失败")

if __name__ == "__main__":
    main()