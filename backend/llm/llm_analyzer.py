import json
import os
from openai import OpenAI

class LLMAnalyzer:
    def __init__(self):
        self.client = OpenAI(
            api_key="sk-1d620b7df9ea4c36b88b06598b3ad19d",
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        self.model_name = "qwen-plus"
    
    def load_anomalies_data(self, data_dir='./data/'):
        """加载异常数据"""
        anomalies_file = os.path.join(data_dir, 'anomalies.ndjson')
        summary_file = os.path.join(data_dir, 'summary.json')
        
        anomalies = []
        summary = {}
        
        # 读取异常记录
        if os.path.exists(anomalies_file):
            with open(anomalies_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        anomalies.append(json.loads(line.strip()))
        
        # 读取摘要信息
        if os.path.exists(summary_file):
            with open(summary_file, 'r', encoding='utf-8') as f:
                summary = json.load(f)
        
        return anomalies, summary
    
    def generate_analysis_prompt(self, anomalies, summary):
        """生成分析提示词"""
        # 统计异常类型
        anomaly_stats = {}
        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            severity = anomaly.get('severity', 'unknown')
            if anomaly_type not in anomaly_stats:
                anomaly_stats[anomaly_type] = {'total': 0, 'severities': {}}
            anomaly_stats[anomaly_type]['total'] += 1
            anomaly_stats[anomaly_type]['severities'][severity] = \
                anomaly_stats[anomaly_type]['severities'].get(severity, 0) + 1
        
        # 构建统计信息字符串
        stats_str = "异常统计信息:\n"
        for anomaly_type, stats in anomaly_stats.items():
            stats_str += f"- {anomaly_type.upper()}: {stats['total']} 次\n"
            for severity, count in stats['severities'].items():
                stats_str += f"  * {severity}: {count} 次\n"
        
        # 构建详细异常信息
        details_str = "详细异常记录:\n"
        for i, anomaly in enumerate(anomalies[:10], 1):  # 限制前10条避免过长
            details_str += f"{i}. 类型: {anomaly.get('type', 'unknown')}, "
            details_str += f"严重性: {anomaly.get('severity', 'unknown')}, "
            details_str += f"时间: {anomaly.get('detected_at', 'unknown')}\n"
            details_str += f"   信息: {anomaly.get('message', '')[:100]}...\n"
        
        prompt = f"""
您是一名专业的系统运维专家，请基于以下操作系统异常检测数据进行分析：

{stats_str}

{details_str}

摘要信息:
- 总异常数: {summary.get('total_anomalies', 0)}
- 按严重性分布: {json.dumps(summary.get('by_severity', {}), ensure_ascii=False)}
- 最后检测时间: {summary.get('last_detection', '未知')}

请从以下三个方面进行专业分析：

1. 当前操作系统隐患分析：
   - 识别主要的系统风险类型
   - 分析各类异常的严重程度和影响范围
   - 评估系统的整体健康状态

2. 针对性建议：
   - 针对每种异常类型提供具体的解决建议
   - 提出系统优化和预防措施
   - 推荐必要的监控和告警设置

3. 总结：
   用一段简洁专业的话总结当前系统状态和主要建议，突出重点。

请确保分析语言清晰、专业、有逻辑，面向技术管理人员。
"""
        return prompt
    
    def analyze_system_anomalies(self, data_dir='./data'):
        """分析系统异常并生成报告"""
        try:
            # 加载数据
            anomalies, summary = self.load_anomalies_data(data_dir)
            
            if not anomalies:
                return "未发现异常数据，系统运行正常。"
            
            # 生成提示词
            prompt = self.generate_analysis_prompt(anomalies, summary)
            
            # 调用大模型
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一名专业的系统运维专家，擅长分析操作系统异常和提供优化建议。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3  # 降低随机性，保证专业性和一致性
            )
            
            result = response.choices[0].message.content.strip()
            return result
            
        except Exception as e:
            return f"分析过程中出现错误: {str(e)}"
    
    def save_analysis_report(self, output_file, analysis_result):
        """保存分析报告"""
        try:
            directory = os.path.dirname(os.path.abspath(output_file))
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("操作系统异常智能分析报告\n")
                f.write("基于大语言模型的专业分析\n")
                f.write("=" * 60 + "\n\n")
                f.write(analysis_result)
            
            print(f"📊 LLM分析报告已保存至: {os.path.abspath(output_file)}")
            return True
            
        except Exception as e:
            print(f"❌ 保存LLM分析报告失败: {e}")
            return False