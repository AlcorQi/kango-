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
            'detection_mode': 'mixed',  # 全局检测模式: keyword, regex, mixed
            'log_paths': [
                '/var/log',
                './backend/log/test.log'
            ],
            'detectors': {
                'oom': {
                    'enabled': True,
                    'detection_mode': 'mixed',  # 可单独覆盖全局模式
                    'keywords': [
                        'Out of memory',
                        'oom-killer',
                        'Killed process',
                        'Memory cgroup out of memory'
                    ],
                    'regex_patterns': [
                        r'Out\s+of\s+memory',
                        r'oom[\-\s]*killer',
                        r'Killed\s+process\s+\d+',
                        r'Memory\s+cgroup\s+out\s+of\s+memory'
                    ]
                },
                'panic': {
                    'enabled': True,
                    'detection_mode': 'mixed',
                    'keywords': [
                        'Kernel panic',
                        'kernel panic',
                        'not syncing',
                        'System halted',
                        'sysrq triggered crash',
                        'Unable to mount root'
                    ],
                    'regex_patterns': [
                        r'Kernel\s+panic',
                        r'not\s+syncing',
                        r'System\s+halted',
                        r'sysrq\s+triggered\s+crash',
                        r'Unable\s+to\s+mount\s+root'
                    ]
                },
                'reboot': {
                    'enabled': True,
                    'detection_mode': 'mixed',
                    'keywords': [
                        'unexpectedly shut down',
                        'unexpected restart',
                        'system reboot',
                        'restart triggered by hardware'
                    ],
                    'regex_patterns': [
                        r'unexpectedly\s+shut\s+down',
                        r'unexpected\s+restart',
                        r'system\s+reboot',
                        r'restart\s+triggered\s+by\s+hardware'
                    ]
                },
                'oops': {
                    'enabled': True,
                    'detection_mode': 'mixed',
                    'keywords': [
                        'Oops:',
                        'general protection fault',
                        'kernel BUG at',
                        'Unable to handle kernel',
                        'WARNING: CPU:',
                        'BUG: unable to handle kernel',
                        'invalid opcode:',
                        'stack segment:'
                    ],
                    'regex_patterns': [
                        r'Oops:',
                        r'general\s+protection\s+fault',
                        r'kernel\s+BUG\s+at',
                        r'Unable\s+to\s+handle\s+kernel',
                        r'WARNING:\s+CPU:',
                        r'BUG:\s+unable\s+to\s+handle\s+kernel',
                        r'invalid\s+opcode:',
                        r'stack\s+segment:'
                    ]
                },
                'deadlock': {
                    'enabled': True,
                    'detection_mode': 'mixed',
                    'keywords': [
                        'possible deadlock',
                        'lock held',
                        'blocked for',
                        'stalled for',
                        'hung task',
                        'task blocked',
                        'soft lockup',
                        'hard lockup',
                        'blocked for more than 120 seconds',
                        'task hung',
                        'Show Blocked State',
                        'Call Trace for'
                    ],
                    'regex_patterns': [
                        r'possible\s+deadlock',
                        r'lock\s+held',
                        r'blocked\s+for',
                        r'stalled\s+for',
                        r'hung\s+task',
                        r'task\s+blocked',
                        r'soft\s+lockup',
                        r'hard\s+lockup',
                        r'blocked\s+for\s+more\s+than\s+\d+\s+seconds',
                        r'task\s+hung',
                        r'Show\s+Blocked\s+State',
                        r'Call\s+Trace\s+for'
                    ]
                },
                'fs_exception': {
                    'enabled': True,
                    'detection_mode': 'mixed',
                    'keywords': [
                        'filesystem error',
                        'EXT4-fs error',
                        'XFS error',
                        'I/O error',
                        'file system corruption',
                        'superblock corrupt',
                        'metadata corruption',
                        'fsck needed',
                        'Buffer I/O error'
                    ],
                    'regex_patterns': [
                        r'filesystem\s+error',
                        r'EXT4-fs\s+error',
                        r'XFS\s+error',
                        r'I/O\s+error',
                        r'file\s+system\s+corruption',
                        r'superblock\s+corrupt',
                        r'metadata\s+corruption',
                        r'fsck\s+needed',
                        r'Buffer\s+I/O\s+error'
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
        detector_config = self.config.get('detectors', {}).get(detector_name, {})
        
        # 如果没有设置检测器特定的模式，使用全局模式
        if 'detection_mode' not in detector_config:
            detector_config['detection_mode'] = self.config.get('detection_mode', 'keyword')
            
        return detector_config
    
    def get_log_paths(self):
        """获取日志路径配置"""
        return self.config.get('log_paths', [])
    
    def get_global_detection_mode(self):
        """获取全局检测模式"""
        return self.config.get('detection_mode', 'keyword')