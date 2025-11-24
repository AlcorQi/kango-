import requests
import json
import time

# 测试SSE连接
print('正在连接SSE流...')
try:
    response = requests.get('http://localhost:8000/api/v1/stream', 
                         headers={'Accept': 'text/event-stream', 'Cache-Control': 'no-cache'}, 
                         stream=True, timeout=10)
    print(f'状态码: {response.status_code}')
    print(f'响应头: {dict(response.headers)}')
    
    # 读取前几行数据
    print('接收到的数据:')
    start_time = time.time()
    for i, line in enumerate(response.iter_lines()):
        if line:
            decoded_line = line.decode('utf-8')
            print(f'行 {i}: {decoded_line}')
            # 检查是否是初始连接事件
            if 'event: open' in decoded_line:
                print('✓ 收到初始连接确认')
            elif 'data:' in decoded_line:
                try:
                    data_str = decoded_line.replace('data: ', '')
                    data = json.loads(data_str)
                    print(f'✓ 收到数据: {data}')
                except:
                    pass
        
        # 读取3秒后停止
        if time.time() - start_time > 3:
            break
            
    response.close()
    print('SSE连接测试完成 - 连接正常！')
except Exception as e:
    print(f'错误: {e}')