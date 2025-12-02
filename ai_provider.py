import os
import time
import urllib.request
import urllib.error
import sys
import subprocess
from config import read_config


class AIProvider:
    """AI 建议提供者

    设计目标：
    - 网页端和后端可以不在同一台机器
    - AI 建议内容通过 HTTP 从外部服务获取，或从本地报告文件回退
    """

    def __init__(self):
        # 可选：从环境变量读取远程 LLM 报告服务地址，例如
        #   export LLM_REPORT_URL="http://analysis-host:9000/llm_analysis.md"
        self.remote_url = os.environ.get("LLM_REPORT_URL") or os.environ.get("LLM_ANALYSIS_URL")

        # 本地回退：backend/report/llm_analysis.txt
        root = os.path.dirname(os.path.abspath(__file__))
        self.llm_report_path = os.path.join(root, "backend", "report", "llm_analysis.txt")

    # ---------- 数据源实现 ----------
    def _fetch_remote_markdown(self) -> str | None:
        """优先从远程 HTTP 服务获取 Markdown 内容."""
        if not self.remote_url:
            return None
        try:
            with urllib.request.urlopen(self.remote_url, timeout=10) as resp:
                data = resp.read()
                text = data.decode(resp.headers.get_content_charset() or "utf-8", errors="ignore")
                return text.strip() or None
        except (urllib.error.URLError, TimeoutError, OSError):
            # 网络失败时回退到本地文件
            return None

    def _load_local_markdown(self) -> str | None:
        """从本地 llm_analysis.txt 读取 Markdown 内容."""
        try:
            if not os.path.exists(self.llm_report_path):
                return None
            with open(self.llm_report_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                return content or None
        except Exception:  # noqa: BLE001
            return None

    def _load_markdown(self) -> str:
        """统一入口：优先 HTTP，失败则本地，最后返回说明性占位文本。"""
        text = self._fetch_remote_markdown()
        if text:
            return text

        text = self._load_local_markdown()
        if text:
            return text

        # 两种方式都失败时的提示
        lines = [
            "### 暂无 LLM 分析报告",
            "",
            "- 当前既没有可访问的远程 LLM 报告服务 (`LLM_REPORT_URL`)，",
            "  也没有本地 `backend/report/llm_analysis.txt` 文件。",
            "- 请确认分析服务已运行，并在后端环境中配置 `LLM_REPORT_URL`，",
            "  或在后端机器上执行离线分析命令生成报告，例如：",
            "",
            "```bash",
            "python backend/main.py --detection-mode mixed --llm-analysis",
            "```",
        ]
        return "\n".join(lines)

    # ---------- 对外接口 ----------
    def suggestions(self, window, types, host_id, limit):
        """获取 AI 建议（Markdown 格式）"""
        markdown = self._load_markdown()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return {
            "items": [
                {
                    "id": "llm-analysis",
                    "title": "LLM 分析报告",
                    "markdown": markdown,
                    "updated_at": now,
                }
            ],
            "generated_at": now,
            "cache_ttl_sec": 600,
        }

    def generate(self, window=None, types=None, host_id=None, timeout_sec=60):
        py = sys.executable or 'python'
        root = os.path.dirname(os.path.abspath(__file__))
        main_py = os.path.join(root, 'backend', 'main.py')
        cfg = read_config()
        mode = (cfg.get('detection', {}) or {}).get('search_mode', 'mixed')
        cmd = [py, main_py, '--detection-mode', mode, '--llm-analysis']
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        try:
            p = subprocess.run(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='ignore', timeout=timeout_sec, env=env)
            out = (p.stdout or '').strip()
            return {
                "returncode": p.returncode,
                "output": out,
                "generated": p.returncode == 0,
                "report_path": self.llm_report_path,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        except Exception as e:
            return {
                "returncode": 1,
                "output": str(e),
                "generated": False,
                "report_path": self.llm_report_path,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }


# 全局 AI 提供者实例
ai_provider = AIProvider()
