from app import create_app, socketio
from config import Config
import logging
# 屏蔽开发服务器警告
cli = logging.getLogger('flask.app')
cli.setLevel(logging.ERROR)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = create_app()

if __name__ == '__main__':
    print("[-] iOS App 隐私合规检测服务启动中: http://127.0.0.1:8080")
    # 使用 socketio.run 启动
    socketio.run(app, host='0.0.0.0', port=Config.SERVER_PORT, debug=Config.DEBUG, allow_unsafe_werkzeug=True)