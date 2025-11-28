from flask import Flask, jsonify
from flask_cors import CORS  # 用于处理跨域请求

# 初始化 Flask 应用
app = Flask(__name__)

# 配置跨域：允许所有来源（*）的访问，支持所有 HTTP 方法和自定义请求头
# 生产环境建议指定具体允许的域名（如 origins=["https://your-domain.com"]）
CORS(
    app,
    origins="*",  # 允许所有 IP/域名跨域（开发环境可用，生产环境需限制）
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # 允许的 HTTP 方法
    allow_headers="*",  # 允许所有请求头
    supports_credentials=True  # 支持跨域携带 Cookie（如需关闭可设为 False）
)

# 测试接口：GET 请求示例
@app.route("/api/hello", methods=["GET"])
def hello_world():
    return jsonify({
        "code": 200,
        "message": "跨域服务运行正常！",
        "data": {
            "port": 5789,
            "allow_origin": "所有 IP",
            "method": "GET"
        }
    })

# 测试接口：POST 请求示例（支持跨域提交数据）
@app.route("/api/submit", methods=["POST"])
def submit_data():
    return jsonify({
        "code": 200,
        "message": "POST 数据接收成功（跨域支持）",
        "data": {"received": True}
    })

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5789,
        debug=True
    )