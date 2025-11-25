import os
import yaml

class ConfigManager:
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.default_config = self.get_default_config()
        self.config = self.load_config()
    
    def get_default_config(self):
        """获取默认配置"""
        return {
            'log_paths': [
                '/var/log',
                './backend/log/test.log'
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
                        'System halted',
                        'sysrq triggered crash',  # 新增关键词
                        'Unable to mount root'    # 新增关键词
                    ]
                },
                'reboot': {
                    'enabled': True,
                    'keywords': [
                        'unexpectedly shut down',
                        'unexpected restart',
                        'system reboot',
                        'restart triggered by hardware'  # 新增关键词
                    ]
                },
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
                        'hard lockup',
                        'blocked for more than 120 seconds',  # 新增关键词
                        'task hung',  # 新增关键词
                        'Show Blocked State',  # 新增关键词
                        'Call Trace for'  # 新增关键词
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
                        'fsck needed',
                        'Buffer I/O error'  # 新增关键词
                    ]
                }
            }
        }
    
    def load_config(self):
        """加载配置文件"""
        if not self.config_path or not os.path.exists(self.config_path):
            print(f"⚠️  警告: 配置文件 {self.config_path} 不存在，使用默认配置")
            return self.default_config

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
            
            # 深度合并配置
            config = self.default_config.copy()
            for key in user_config:
                if key in config and isinstance(config[key], dict):
                    config[key].update(user_config[key])
                else:
                    config[key] = user_config[key]
            
            return config
        except Exception as e:
            print(f"❌ 错误: 无法加载配置文件 {self.config_path}: {e}")
            return self.default_config
    
    def get_detector_config(self, detector_name):
        """获取指定检测器的配置"""
        return self.config.get('detectors', {}).get(detector_name, {})
    
    def get_log_paths(self):
        """获取日志路径配置"""
        return self.config.get('log_paths', [])