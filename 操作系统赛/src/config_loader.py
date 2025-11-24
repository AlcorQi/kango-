import yaml
import os

class ConfigLoader:
    def __init__(self):
        self.default_config = {
            'log_paths': [
                '/var/log/kern.log',
                '/var/log/syslog'
            ],
            'detectors': {}
        }
    
    def load_config(self, config_path='config/default.yaml'):
        """加载配置文件"""
        if not os.path.exists(config_path):
            print(f"⚠️  警告: 配置文件 {config_path} 不存在，使用默认配置")
            return self.default_config
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
                # 合并默认配置
                merged_config = self.default_config.copy()
                if config:
                    merged_config.update(config)
                    
                return merged_config
                
        except Exception as e:
            print(f"❌ 错误: 无法加载配置文件 {config_path}: {e}")
            return self.default_config
