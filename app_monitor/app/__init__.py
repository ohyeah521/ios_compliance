# app/__init__.py

from flask import Flask
from flask_socketio import SocketIO
from config import Config

socketio = SocketIO(async_mode='threading') 

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    from app.api.routes import api_bp
    from app.web.routes import web_bp
    
    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)

    # 初始化时也无需再次指定 async_mode，因为上面已经指定了，或者直接留空
    socketio.init_app(app, cors_allowed_origins='*') 

    return app