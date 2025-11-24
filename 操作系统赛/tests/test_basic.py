#!/usr/bin/env python3
import sys
import os

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from src.main import ExceptionMonitor

def create_test_data():
    """创建测试数据"""
    test_content = [
        "[2024-01-15 14:30:25] Out of memory: Killed process 2587 (chrome)",
        "[2024-01-15 14:31:00] Kernel panic - not syncing: VFS: Unable to mount root fs",
        "[2024-01-16 09:15:33] system unexpectedly shut down due to power failure",
        "[2024-01-17 11:20:45] Normal system operation",
        "[2024-01-18 08:05:12] oom-killer invoked by init process",
        "[2024-01-19 13:40:22] Killed process 4231 (firefox)"
    ]
    
    with open('../test.log', 'w') as f:
        for line in test_content:
            f.write(line + '\n')
    
    print("✅ 测试数据已创建: ../test.log")

def test_basic_detection():
    """基础功能测试"""
    print("\n🧪 开始基础功能测试...")
    
    # 创建测试数据
    create_test_data()
    
    # 测试检测器
    monitor = ExceptionMonitor('../config/default.yaml')
    
    # 测试OOM检测
    test_cases = [
        ("Out of memory: Killed process 2567 (java)", "oom"),
        ("kernel panic detected at address 0xffffffff", "panic"), 
        ("system unexpectedly shut down", "reboot")
    ]
    
    passed_tests = 0
    for test_line, expected_type in test_cases:
        for detector in monitor.detectors:
            result = detector.detect(test_line)
            if result and result['type'] == expected_type:
                print(f"✅ {expected_type.upper()}检测器工作正常")
                passed_tests += 1
                break
    
    print(f"\n📊 测试结果: {passed_tests}/{len(test_cases)} 项通过")
    
    if passed_tests == len(test_cases):
        print("🎉 所有基础测试通过!")
    else:
        print("❌ 部分测试失败，请检查!")

if __name__ == "__main__":
    test_basic_detection()
