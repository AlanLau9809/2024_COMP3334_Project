# run.py - Flask 應用啟動入口
import os
from dotenv import load_dotenv  # 用於加載環境變量
from app import create_app, db
from app.models import User, File, FileShare, AuditLog  # 導入所有資料庫模型
from flask_login import LoginManager

# 加載環境變量（如果使用 .env 文件）
# load_dotenv()

# 創建 Flask 應用實例
app = create_app()

# initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  # 設定未登入用戶的跳轉頁面

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login 所需的用戶加載函數"""
    return User.query.get(int(user_id))

# CLI 命令（可選，用於手動初始化資料庫）
@app.cli.command('init-db')
def init_db():

    with app.app_context():
        db.create_all()
    print("Database tables created!")

if __name__ == '__main__':
    # 啟動 Flask 開發伺服器
    app.run(
        host='0.0.0.0',  # 允許外部訪問
        port=5000,
        debug=True       # 開發模式開啟調試（生產環境應設為 False）
    )