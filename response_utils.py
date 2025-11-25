import json

def json_response(handler, obj, status=200):
    """发送 JSON 响应"""
    body = json.dumps(obj).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

def error_response(handler, status, code, message, details=None):
    """发送错误响应"""
    json_response(handler, {
        "status": status,
        "code": code,
        "message": message,
        "trace_id": "",
        "details": details or {}
    }, status=status)