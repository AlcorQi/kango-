# 正则表达式检测规则说明文档

## 概述

本项目支持三种检测模式，新的正则表达式设计能够处理：
1. **被分隔的关键词** - 关键词中间插入其他内容
2. **内在规律** - 基于错误模式的规律而非固定关键词
3. **变体表达** - 同一概念的不同表达方式

## 正则表达式设计原则

### 1. 使用非贪婪匹配处理分隔关键词
- `.*?` 匹配任意字符（非贪婪），允许关键词之间插入内容
- 例如：`Out.*?of.*?memory` 可以匹配 "Out of memory"、"Out - of - memory" 等

### 2. 使用分组和可选匹配处理变体
- `(?:pattern1|pattern2)` 非捕获组，匹配多个变体
- 例如：`(?:kill|terminat)` 匹配 "kill" 或 "terminate"

### 3. 基于内在规律而非固定关键词
- 匹配错误代码模式、数字模式、地址模式等
- 例如：`IP.*?[\da-fA-Fx]+` 匹配指令指针地址

## 正则表达式规则详解

### OOM (内存不足) 检测
- `(?:Out\s+of\s+memory|OOM).*?(?:kill|terminat).*?process.*?\d+`
  - 匹配各种OOM表达方式，包括被分隔的短语
  - 示例匹配："Out - of - memory: kill process 1234"

- `oom.*?killer.*?invoked.*?(?:gfp_mask|order)=\w+`
  - 匹配oom-killer调用及其参数
  - 示例匹配："oom killer invoked gfp_mask=0x201da"

- `(?:Killed|terminated).*?process.*?\d+.*?(?:total-vm|rss).*?\d+[kKmMgG]?B`
  - 匹配进程终止及内存统计信息
  - 示例匹配："Killed process 1234 total-vm:123456kB"

### Kernel Panic 检测
- `(?:Kernel|kernel).*?panic.*?(?:not.*?syncing|System.*?halted)`
  - 匹配各种内核恐慌表达方式
  - 示例匹配："Kernel panic - not syncing: System halted"

- `panic.*?(?:CPU|PID).*?\d+.*?(?:not.*?syncing|System.*?halted)`
  - 匹配包含CPU/PID信息的恐慌
  - 示例匹配："panic: CPU 1 PID 1234 not syncing"

- `(?:sysrq|SysRq).*?trigger.*?crash.*?Kernel.*?panic`
  - 匹配SysRq触发的崩溃
  - 示例匹配："sysrq triggered crash - Kernel panic"

### 系统重启检测
- `(?:unexpected|unclean).*?(?:shut.*?down|restart|reboot)`
  - 匹配各种意外重启表达方式
  - 示例匹配："unexpected system shut down"

- `system.*?(?:reboot|restart).*?(?:initiated|triggered)`
  - 匹配系统重启的各种表达
  - 示例匹配："system reboot initiated by user"

### OOPS 检测
- `Oops.*?(?:general protection|GPF).*?IP.*?[\da-fA-Fx]+`
  - 匹配Oops错误及指令指针
  - 示例匹配："Oops: general protection fault IP: ffffffff12345678"

- `(?:kernel|Kernel).*?BUG.*?at.*?[\w/]+\.(?:c|h):\d+`
  - 匹配内核BUG位置信息
  - 示例匹配："kernel BUG at /path/to/file.c:123"

- `Call.*?Trace.*?(?:\[\w+\]|do_one_initcall)`
  - 匹配调用栈跟踪模式
  - 示例匹配："Call Trace: [<ffffffff12345678>] do_one_initcall+0x50/0x100"

### 死锁检测
- `(?:possible|potential).*?deadlock.*?(?:detected|found)`
  - 匹配可能的死锁检测
  - 示例匹配："possible deadlock detected in driver"

- `INFO.*?task.*?blocked.*?more.*?\d+.*?seconds`
  - 匹配任务阻塞超时信息
  - 示例匹配："INFO: task java blocked for more than 120 seconds"

- `(?:soft|hard).*?lockup.*?CPU.*?\d+.*?stuck.*?\d+`
  - 匹配软硬锁死信息
  - 示例匹配："soft lockup detected on CPU 1 stuck for 10s"

### 文件系统异常检测
- `(?:filesystem|file system).*?error.*?(?:corrupt|damage)`
  - 匹配文件系统错误及损坏
  - 示例匹配："filesystem error: superblock corrupt"

- `(?:EXT4|XFS|BTRFS|NTFS).*?(?:error|corruption).*?detected`
  - 匹配各种文件系统错误
  - 示例匹配："EXT4-fs error (device sda1): corruption detected"

- `I/O.*?error.*?dev.*?\w+.*?(?:sector|logical).*?\d+`
  - 匹配I/O错误及设备信息
  - 示例匹配："I/O error on device sda1 sector 123456"

## 测试示例

### 测试非标准格式日志
```python
import re

# 测试被分隔的OOM日志
pattern = r'(?:Out\s+of\s+memory|OOM).*?(?:kill|terminat).*?process.*?\d+'
test_lines = [
    "Out of memory: kill process 1234",  # 标准格式
    "OOM - killing process 5678",        # 分隔格式
    "Out of memory: terminate task 9012" # 变体表达
]

for line in test_lines:
    if re.search(pattern, line, re.IGNORECASE):
        print(f"匹配: {line}")

# 测试内在规律（调用栈）
pattern = r'Call.*?Trace.*?(?:\[\w+\]|do_one_initcall)'
test_lines = [
    "Call Trace:",
    "Call Trace for deadlock:",
    "Backtrace: [<ffffffff12345678>] do_one_initcall+0x50/0x100"
]

for line in test_lines:
    if re.search(pattern, line, re.IGNORECASE):
        print(f"匹配调用栈: {line}")