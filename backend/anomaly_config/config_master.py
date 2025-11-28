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
            'detection_mode': 'mixed',
            'log_paths': [
                '/var/log',
                './backend/log/test.log'
            ],
            'detectors': {
                'oom': {
                    'enabled': True,
                    'detection_mode': 'mixed',
                    'keywords': [
                        'Out of memory',
                        'oom-killer',
                        'Killed process',
                        'Memory cgroup out of memory'
                    ],
                    'regex_patterns': [
                        # 匹配各种OOM模式，包括被分隔的关键词和内存模式
                        r'(?:Out\s+of\s+memory|OOM).*?(?:kill|terminat).*?process.*?\d+',
                        r'oom.*?killer.*?invoked.*?(?:gfp_mask|order)=\w+',
                        r'(?:Killed|terminated).*?process.*?\d+.*?(?:total-vm|rss).*?\d+[kKmMgG]?B',
                        r'Memory.*?cgroup.*?out.*?memory.*?(?:usage|limit).*?\d+',
                        r'oom_score.*?\d+.*?pid.*?\d+.*?total_vm.*?\d+',
                        r'page allocation failure.*?order.*?\d+',
                        r'compact.*?failed.*?order.*?\d+',
                        r'swap.*?full.*?cannot.*?swap.*?out'
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
                        # 匹配内核恐慌的各种模式，包括被分隔的短语
                        r'(?:Kernel|kernel).*?panic.*?(?:not.*?syncing|System.*?halted)',
                        r'panic.*?(?:CPU|PID).*?\d+.*?(?:not.*?syncing|System.*?halted)',
                        r'(?:sysrq|SysRq).*?trigger.*?crash.*?Kernel.*?panic',
                        r'(?:Unable to mount|Cannot mount).*?root.*?(?:filesystem|device)',
                        r'(?:VFS|Virtual File System).*?mount.*?root.*?failed',
                        r'end.*?Kernel.*?panic.*?(?:not.*?tty|sysrq)',
                        r'BUG.*?unable.*?handle.*?(?:kernel|NULL).*?at.*?0x[\da-fA-F]+',
                        r'general protection fault.*?ip:.*?[\da-fA-F]+.*?error:.*?\d+'
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
                        # 匹配重启相关的模式，包括各种表达方式
                        r'(?:unexpected|unclean).*?(?:shut.*?down|restart|reboot)',
                        r'system.*?(?:reboot|restart).*?(?:initiated|triggered)',
                        r'(?:watchdog|hardware).*?trigger.*?(?:reboot|restart)',
                        r'power.*?(?:failure|loss).*?shut.*?down',
                        r'ACPI.*?enter.*?(?:S5|shutdown|reboot)',
                        r'systemd.*?reboot.*?target.*?start',
                        r'kernel.*?restart.*?preparing',
                        r'emergency.*?restart.*?initiated'
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
                        # 匹配Oops和内核错误的各种模式
                        r'Oops.*?(?:general protection|GPF).*?IP.*?[\da-fA-Fx]+',
                        r'(?:kernel|Kernel).*?BUG.*?at.*?[\w/]+\.(?:c|h):\d+',
                        r'(?:Unable to handle|Cannot handle).*?(?:kernel|NULL).*?pointer',
                        r'WARNING.*?CPU.*?\d+.*?PID.*?\d+.*?at.*?[\w/]+',
                        r'BUG.*?unable.*?handle.*?(?:kernel|page).*?fault',
                        r'invalid.*?opcode.*?IP.*?[\da-fA-Fx]+',
                        r'stack.*?segment.*?fault.*?address.*?[\da-fA-Fx]+',
                        r'RIP.*?[\da-fA-Fx]+.*?Code.*?(?:Oops|BUG)',
                        r'Call.*?Trace.*?(?:\[\w+\]|do_one_initcall)',
                        r'divide.*?error.*?CPU.*?\d+.*?IP.*?[\da-fA-Fx]+'
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
                        # 匹配死锁的各种模式
                        r'(?:possible|potential).*?deadlock.*?(?:detected|found)',
                        r'INFO.*?task.*?blocked.*?more.*?\d+.*?seconds',
                        r'task.*?\w+.*?state.*?[RD].*?blocked.*?\d+.*?seconds',
                        r'(?:soft|hard).*?lockup.*?CPU.*?\d+.*?stuck.*?\d+',
                        r'hung.*?task.*?state.*?[RD].*?blocked',
                        r'Show.*?Blocked.*?State.*?task.*?state.*?[RD]',
                        r'Call.*?Trace.*?for.*?(?:mutex_lock|spin_lock)',
                        r'detected.*?deadlock.*?between.*?\w+.*?and.*?\w+',
                        r'lock.*?held.*?by.*?\w+.*?waiting.*?for.*?\w+',
                        r'circular.*?dependency.*?detected.*?\w+.*?\w+'
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
                        # 匹配文件系统错误的各种模式
                        r'(?:filesystem|file system).*?error.*?(?:corrupt|damage)',
                        r'(?:EXT4|XFS|BTRFS|NTFS).*?(?:error|corruption).*?detected',
                        r'I/O.*?error.*?dev.*?\w+.*?(?:sector|logical).*?\d+',
                        r'(?:superblock|metadata).*?corrupt.*?(?:run.*?fsck|repair)',
                        r'Buffer.*?I/O.*?error.*?dev.*?\w+.*?logical.*?\d+',
                        r'journal.*?abort.*?I/O.*?error',
                        r'file.*?system.*?corruption.*?(?:detected|found)',
                        r'fsck.*?needed.*?(?:filesystem|partition)',
                        r'read.*?error.*?sector.*?\d+.*?device.*?\w+',
                        r'write.*?error.*?sector.*?\d+.*?device.*?\w+'
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