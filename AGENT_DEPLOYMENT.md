# 分布式异常检测系统部署指南

## 架构说明

本系统支持两种运行模式：

1. **单机模式**：服务器本地检测（传统模式）
2. **分布式模式**：Agent + 中心服务器（推荐用于多机器监控）

## 快速开始

### 1. 启动中心服务器

```bash
# 启动服务器（默认端口 8000）
python server.py

# 或指定端口
python server.py --port 8080
```

服务器启动后会：
- 提供 Web 前端界面（`http://localhost:8000`）
- 提供 Agent 上报接口（`POST http://localhost:8000/api/v1/ingest`）
- 根据配置决定是否启用本地检测循环

### 2. 配置服务器

编辑 `config/config.json`：

```json
{
  "detection": {
    "local_detection_enabled": false,  // 设为 false 禁用本地检测，仅接收 Agent 上报
    "search_mode": "mixed",             // 检测模式：keyword / regex / mixed
    "scan_interval_sec": 60
  },
  "security": {
    "ingest_token": "your-secret-token"  // Agent 认证 token（可选）
  }
}
```

### 3. 在被检测设备上部署 Agent

#### 方式一：直接运行

```bash
# 基本使用
python agent.py --server http://your-server:8000

# 使用认证 token
python agent.py --server http://your-server:8000 --token your-secret-token

# 指定检测模式
python agent.py --server http://your-server:8000 --detection-mode mixed

# 使用自定义配置
python agent.py --server http://your-server:8000 --config /path/to/config.json
```

#### 方式二：作为系统服务（systemd）

创建 `/etc/systemd/system/anomaly-agent.service`：

```ini
[Unit]
Description=Anomaly Detection Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/anomaly-detection
ExecStart=/usr/bin/python3 /opt/anomaly-detection/agent.py --server http://your-server:8000 --token your-secret-token
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable anomaly-agent
sudo systemctl start anomaly-agent
sudo systemctl status anomaly-agent
```

## 功能特性

### 1. Agent + 中心服务架构

- **Agent**：在被检测设备上运行，负责：
  - 扫描本地日志文件
  - 检测异常事件
  - 通过网络上报到中心服务器

- **中心服务器**：负责：
  - 接收 Agent 上报的数据
  - 存储异常事件
  - 提供 Web 界面展示
  - 可选：本地检测（如果启用）

### 2. 分布式监控

- 一个前端页面可以监控多个机器
- 支持按机器筛选查看异常
- 自动发现已注册的机器列表

### 3. 检测循环

- **服务器端**：如果 `local_detection_enabled: true`，会定期扫描配置的日志路径
- **Agent 端**：根据配置的 `scan_interval_sec` 定期检测和上报

### 4. 机器标识

系统使用 `host_id` 标识机器，默认使用 `socket.gethostname()`。

Agent 会自动使用本机主机名作为 `host_id`，你也可以在 Agent 代码中自定义。

## API 接口

### Agent 上报接口

**POST** `/api/v1/ingest`

请求头：
```
Content-Type: application/json
X-Ingest-Token: your-token (可选)
```

请求体（单个事件）：
```json
{
  "type": "oom",
  "severity": "major",
  "message": "Out of memory: Killed process 1234",
  "source_file": "/var/log/syslog",
  "line_number": 12345,
  "detected_at": "2025-11-30T12:00:00Z",
  "host_id": "server-01"
}
```

请求体（批量事件）：
```json
{
  "events": [
    {
      "type": "oom",
      "severity": "major",
      "message": "...",
      "host_id": "server-01"
    },
    {
      "type": "kernel_panic",
      "severity": "critical",
      "message": "...",
      "host_id": "server-01"
    }
  ]
}
```

### 获取机器列表

**GET** `/api/v1/hosts`

响应：
```json
{
  "hosts": ["server-01", "server-02", "server-03"],
  "total": 3
}
```

### 按机器筛选统计

**GET** `/api/v1/stats?host_id=server-01`

## 配置说明

### 服务器配置 (`config/config.json`)

```json
{
  "detection": {
    "local_detection_enabled": false,    // 是否启用本地检测
    "search_mode": "mixed",               // 检测模式
    "scan_interval_sec": 60,              // 扫描间隔（秒）
    "log_paths": ["/var/log"],            // 本地检测的日志路径（如果启用）
    "enabled_detectors": ["oom", "kernel_panic", ...]
  },
  "security": {
    "ingest_token": "your-secret-token"   // Agent 认证 token
  }
}
```

### Agent 配置

Agent 会读取 `config/config.json`（如果存在），或使用命令行参数。

主要配置项：
- `detection.log_paths`：要扫描的日志路径
- `detection.scan_interval_sec`：扫描间隔
- `detection.enabled_detectors`：启用的检测器列表

## 故障排查

### Agent 无法连接到服务器

1. 检查网络连接：`ping your-server`
2. 检查服务器是否运行：`curl http://your-server:8000/api/v1/config`
3. 检查防火墙规则

### Agent 上报失败

1. 检查 token 是否正确（如果服务器配置了 token）
2. 查看 Agent 日志输出
3. 检查服务器日志

### 前端看不到机器

1. 确保 Agent 已成功上报至少一个事件
2. 刷新前端页面
3. 检查 `/api/v1/hosts` 接口返回

## 安全建议

1. **使用 HTTPS**：在生产环境中，建议使用反向代理（如 Nginx）提供 HTTPS
2. **设置认证 Token**：在 `config/config.json` 中配置 `ingest_token`
3. **网络隔离**：Agent 和服务器之间的通信建议在内网进行
4. **定期更新**：保持 Agent 和服务器代码同步更新

## 性能优化

1. **调整扫描间隔**：根据日志量调整 `scan_interval_sec`
2. **限制日志路径**：只扫描必要的日志目录
3. **批量上报**：Agent 会批量上报多个事件，减少网络请求
4. **数据清理**：定期清理过期数据，配置 `retention_days` 和 `retention_max_events`


