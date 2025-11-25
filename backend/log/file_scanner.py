import os
import gzip
import platform
import shutil

class FileScanner:
    def __init__(self, config_manager):
        self.config_manager = config_manager
    
    def collect_log_files(self):
        """收集所有需要扫描的日志文件"""
        files = []
        print("📁 正在收集日志文件...")
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(base_dir)
        
        for p in self.config_manager.get_log_paths():
            abs_path = self.resolve_path(p, base_dir, parent_dir)
            if os.path.isfile(abs_path):
                files.append(abs_path)
                print(f"   📄 添加文件: {abs_path}")
            elif os.path.isdir(abs_path):
                files.extend(self.scan_directory(abs_path))
        
        print(f"   📁 总共找到 {len(files)} 个日志文件")
        return files
    
    def resolve_path(self, path, base_dir, parent_dir):
        """解析相对路径"""
        abs_path = os.path.abspath(path)
        if path.startswith('./') or path.startswith('../'):
            c1 = os.path.abspath(os.path.join(base_dir, path))
            c2 = os.path.abspath(os.path.join(parent_dir, path))
            abs_path = c1 if os.path.exists(c1) else c2
        return abs_path
    
    def scan_directory(self, directory_path):
        """扫描目录中的日志文件"""
        files = []
        for root, dirs, filenames in os.walk(directory_path):
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
    
    def read_log_file(self, log_path):
        """读取日志文件内容"""
        line_count = 0
        lines = []
        
        try:
            # 处理压缩日志文件
            if log_path.endswith('.gz'):
                f = gzip.open(log_path, 'rt', errors='ignore')
            else:
                f = open(log_path, 'r', errors='ignore')
                
            with f as fobj:
                for line in fobj:
                    line_count += 1
                    lines.append(line)
            
            print(f"   共读取 {line_count} 行日志")
            return lines, line_count
            
        except PermissionError:
            print(f"❌ 权限不足，无法读取: {log_path}")
            print("💡 尝试使用 sudo 运行:")
            return [], 0
        except Exception as e:
            print(f"❌ 读取日志文件 {log_path} 出错: {e}")
            return [], 0