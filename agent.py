#!/usr/bin/env python3
"""
分布式异常检测 Agent

在被检测设备上运行此脚本，它会：
1. 定期扫描本地日志文件
2. 检测异常事件
3. 通过网络上报到中心服务器

使用方法：
    python agent.py --server http://your-server:8000 --token your-token
"""

import os
import sys
import json
import time
import socket
import hashlib
import argparse
import requests
import subprocess
from pathlib import Path

# 添加项目路径以便导入检测逻辑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ingest_manager import (
    _match_types, _severity_for, _collect_paths,
    _load_offsets, _save_offsets, REGEX_PATTERNS
)
from config import CONFIG_FILE, SCHEMA_VERSION

class Agent:
    def __init__(self, server_url, token=None, config_path=None, detection_mode='mixed'):
        """
        初始化 Agent
        
        :param server_url: 中心服务器地址，如 'http://192.168.1.100:8000'
        :param token: 可选的认证 token
        :param config_path: 可选的配置文件路径（用于读取 log_paths 等）
        :param detection_mode: 检测模式：keyword / regex / mixed
        """
        self.server_url = server_url.rstrip('/')
        self.ingest_url = f"{self.server_url}/api/v1/ingest"
        self.token = token
        self.config_path = config_path or CONFIG_FILE
        self.detection_mode = detection_mode
        self.host_id = socket.gethostname()
        self.offsets = {}
        self.offsets_file = os.path.join(os.path.dirname(__file__), 'data', 'agent_offsets.json')
        
        # 确保 offsets 目录存在
        os.makedirs(os.path.dirname(self.offsets_file), exist_ok=True)
        
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def get_log_paths(self):
        """获取日志路径列表"""
        cfg = self.load_config()
        paths = cfg.get('detection', {}).get('log_paths', ['/var/log'])
        return paths
    
    def get_enabled_detectors(self):
        """获取启用的检测器列表"""
        cfg = self.load_config()
        return cfg.get('detection', {}).get('enabled_detectors', [
            'oom', 'kernel_panic', 'unexpected_reboot', 'fs_error', 'oops', 'deadlock'
        ])
    
    def get_scan_interval(self):
        """获取扫描间隔（秒）"""
        cfg = self.load_config()
        return int(cfg.get('detection', {}).get('scan_interval_sec', 60))
    
    def get_config_snapshot(self):
        """获取配置快照，用于比较配置是否变更"""
        cfg = self.load_config()
        det = cfg.get('detection', {})
        return {
            'interval': int(det.get('scan_interval_sec', 60)),
            'paths': det.get('log_paths', []),
            'enabled': det.get('enabled_detectors', [])
        }
    
    def get_search_mode(self):
        """获取检测模式（keyword/regex/mixed），优先读取配置文件"""
        cfg = self.load_config()
        mode = (cfg.get('detection', {}) or {}).get('search_mode')
        if mode in ('keyword', 'regex', 'mixed'):
            return mode
        return self.detection_mode
    
    def run_backend_once(self):
        try:
            py = sys.executable or 'python'
            root = os.path.dirname(os.path.abspath(__file__))
            main_py = os.path.join(root, 'backend', 'main.py')
            if not os.path.exists(main_py):
                print(f"[ERROR] 后端入口不存在: {main_py}")
                return 2
            mode = self.get_search_mode()
            cmd = [py, main_py, '--detection-mode', mode]
            print(f"[INFO] 调用后端: {py} {main_py} --detection-mode {mode}")
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            p = subprocess.run(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='ignore', env=env)
            out = (p.stdout or '').strip()
            if out:
                print(out)
            return p.returncode
        except Exception as e:
            print(f"[ERROR] 运行 backend/main.py 失败: {e}", file=sys.stderr)
            return 1
    
    def report_events(self, events):
        """上报事件到中心服务器"""
        try:
            headers = {
                'Content-Type': 'application/json',
            }
            if self.token:
                headers['X-Ingest-Token'] = self.token
            
            payload = {
                "events": events
            }
            
            response = requests.post(
                self.ingest_url,
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"[INFO] 上报成功: {result.get('processed', 0)}/{result.get('received', 0)} 个事件")
                return result.get('processed', 0)
            else:
                print(f"[ERROR] 上报失败: HTTP {response.status_code} - {response.text}", file=sys.stderr)
                return 0
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] 网络错误: {e}", file=sys.stderr)
            return 0
        except Exception as e:
            print(f"[ERROR] 上报异常: {e}", file=sys.stderr)
            return 0
    
    def _load_offsets(self):
        """加载文件偏移量"""
        try:
            if os.path.exists(self.offsets_file):
                with open(self.offsets_file, 'r', encoding='utf-8') as f:
                    self.offsets = json.load(f)
        except:
            self.offsets = {}
    
    def _save_offsets(self):
        """保存文件偏移量"""
        try:
            with open(self.offsets_file, 'w', encoding='utf-8') as f:
                json.dump(self.offsets, f)
        except:
            pass
    
    def run(self):
        """运行 Agent 主循环"""
        print("=" * 60)
        print(f"🤖 异常检测 Agent 启动")
        print(f"   主机ID: {self.host_id}")
        print(f"   服务器: {self.server_url}")
        print(f"   检测模式: {self.get_search_mode()}")
        print("=" * 60)
        
        self._load_offsets()
        last_mode = None
        
        while True:
            try:
                interval = self.get_scan_interval()
                mode = self.get_search_mode()
                if last_mode is None:
                    print(f"[INFO] 当前检测模式：{mode}")
                elif mode != last_mode:
                    print(f"[INFO] 检测模式已切换：{last_mode} -> {mode}")
                last_mode = mode
                print(f"\n[INFO] 开始扫描... ({time.strftime('%Y-%m-%d %H:%M:%S')})")
                
                rc = self.run_backend_once()
                
                if rc == 0:
                    print("[INFO] 后端检测完成")
                else:
                    print("[WARN] 后端检测执行异常")
                
                print(f"[INFO] 等待 {interval} 秒后继续...")
                try:
                    start = max(5, min(3600, int(interval)))
                except:
                    start = 60
                
                # 获取当前配置快照
                current_snap = self.get_config_snapshot()
                
                waited = 0
                while waited < start:
                    new_snap = self.get_config_snapshot()
                    
                    # 如果配置发生变化（间隔、路径或检测器），立即中断等待
                    if (new_snap['interval'] != current_snap['interval'] or 
                        new_snap['paths'] != current_snap['paths'] or 
                        new_snap['enabled'] != current_snap['enabled']):
                        break
                        
                    time.sleep(1)
                    waited += 1
                
            except KeyboardInterrupt:
                print("\n[INFO] 收到中断信号，正在退出...")
                break
            except Exception as e:
                print(f"[ERROR] 运行异常: {e}", file=sys.stderr)
                time.sleep(60)  # 出错后等待1分钟再继续


def main():
    parser = argparse.ArgumentParser(
        description='分布式异常检测 Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本使用
  python agent.py --server http://192.168.1.100:8000
  
  # 使用认证 token
  python agent.py --server http://192.168.1.100:8000 --token my-secret-token
  
  # 指定检测模式
  python agent.py --server http://192.168.1.100:8000 --detection-mode mixed
  
  # 使用自定义配置
  python agent.py --server http://192.168.1.100:8000 --config /path/to/config.json
        """
    )
    
    parser.add_argument(
        '--server',
        required=True,
        help='中心服务器地址，如 http://192.168.1.100:8000'
    )
    
    parser.add_argument(
        '--token',
        help='可选的认证 token（如果服务器配置了 ingest_token）'
    )
    
    parser.add_argument(
        '--config',
        help='配置文件路径（默认使用 config/config.json）'
    )
    
    parser.add_argument(
        '--detection-mode',
        choices=['keyword', 'regex', 'mixed'],
        default='mixed',
        help='检测模式：keyword(纯关键字), regex(纯正则), mixed(混合模式，默认)'
    )
    
    args = parser.parse_args()
    
    agent = Agent(
        server_url=args.server,
        token=args.token,
        config_path=args.config,
        detection_mode=args.detection_mode
    )
    
    agent.run()


if __name__ == '__main__':
    main()


