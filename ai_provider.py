import time

class AIProvider:
    """AI 建议提供者"""
    
    def suggestions(self, window, types, host_id, limit):
        """获取 AI 建议"""
        return {
            "items": [],
            "generated_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "cache_ttl_sec": 600
        }

# 全局 AI 提供者实例
ai_provider = AIProvider()