from flask import Flask
from flask_login import LoginManager
from .models import db
import os


login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # 生成安全的 Secret Key（實際部署時應使用環境變量）
    app.config['SECRET_KEY'] = os.urandom(24)  # 或手動設置一個複雜字符串
    
    # 數據庫 URI 格式：mysql+pymysql://用戶名:密碼@主機:端口/數據庫名
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/online_storage'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 初始化扩展
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # 注册蓝图（关键步骤！）
    from app.routes import auth, main  # 必须在此处导入，避免循环依赖
    app.register_blueprint(auth)
    app.register_blueprint(main)
    
    with app.app_context():
        db.create_all()
    
    return app