# 正则表达式检测规则说明文档

## 概述

本项目支持三种检测模式：
1. **keyword** - 纯关键字匹配（原有功能）
2. **regex** - 纯正则表达式匹配
3. **mixed** - 关键字和正则表达式混合匹配

## 正则表达式规则说明

### OOM (内存不足) 检测
- `Out\s+of\s+memory` - 匹配"Out of memory"及其变体
- `oom[\-\s]*killer` - 匹配"oom-killer"、"oom killer"等
- `Killed\s+process\s+\d+` - 匹配"Killed process 1234"格式
- `Memory\s+cgroup\s+out\s+of\s+memory` - 匹配cgroup内存不足

### Kernel Panic 检测
- `Kernel\s+panic` - 匹配内核恐慌
- `not\s+syncing` - 匹配"not syncing"错误
- `System\s+halted` - 匹配系统停止
- `sysrq\s+triggered\s+crash` - 匹配SysRq触发的崩溃
- `Unable\s+to\s+mount\s+root` - 匹配无法挂载根文件系统

### 系统重启检测
- `unexpectedly\s+shut\s+down` - 匹配意外关机
- `unexpected\s+restart` - 匹配意外重启
- `system\s+reboot` - 匹配系统重启
- `restart\s+triggered\s+by\s+hardware` - 匹配硬件触发的重启

### OOPS 检测
- `Oops:` - 匹配Oops错误
- `general\s+protection\s+fault` - 匹配一般保护错误
- `kernel\s+BUG\s+at` - 匹配内核BUG
- `Unable\s+to\s+handle\s+kernel` - 匹配无法处理的内核错误
- `WARNING:\s+CPU:` - 匹配CPU警告
- `BUG:\s+unable\s+to\s+handle\s+kernel` - 匹配无法处理的内核BUG
- `invalid\s+opcode:` - 匹配无效操作码
- `stack\s+segment:` - 匹配堆栈段错误

### 死锁检测
- `possible\s+deadlock` - 匹配可能的死锁
- `lock\s+held` - 匹配锁持有
- `blocked\s+for` - 匹配阻塞时间
- `stalled\s+for` - 匹配停滞时间
- `hung\s+task` - 匹配挂起任务
- `task\s+blocked` - 匹配任务阻塞
- `soft\s+lockup` - 匹配软锁
- `hard\s+lockup` - 匹配硬锁
- `blocked\s+for\s+more\s+than\s+\d+\s+seconds` - 匹配阻塞超过指定秒数
- `task\s+hung` - 匹配任务挂起
- `Show\s+Blocked\s+State` - 匹配显示阻塞状态
- `Call\s+Trace\s+for` - 匹配调用跟踪

### 文件系统异常检测
- `filesystem\s+error` - 匹配文件系统错误
- `EXT4-fs\s+error` - 匹配EXT4文件系统错误
- `XFS\s+error` - 匹配XFS文件系统错误
- `I/O\s+error` - 匹配I/O错误
- `file\s+system\s+corruption` - 匹配文件系统损坏
- `superblock\s+corrupt` - 匹配超级块损坏
- `metadata\s+corruption` - 匹配元数据损坏
- `fsck\s+needed` - 匹配需要fsck
- `Buffer\s+I/O\s+error` - 匹配缓冲I/O错误

## 使用方式

### 通过配置文件设置
在配置文件的全局设置或单个检测器设置中指定：
```yaml
detection_mode: mixed  # 全局模式

detectors:
  oom:
    enabled: true
    detection_mode: regex  # 单个检测器模式