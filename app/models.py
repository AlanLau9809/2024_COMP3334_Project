from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# 用戶表（對應 SQL 的 User 表）
class User(db.Model):
    __tablename__ = 'User'  # 明確指定表名與 SQL 一致
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 主鍵改名為 user_id
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255))
    is_admin = db.Column(db.SmallInteger, default=0)  # 使用 SmallInteger 對應 TINYINT(1)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 文件表（對應 SQL 的 File 表）
class File(db.Model):
    __tablename__ = 'File'
    file_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.user_id'), nullable=False)  # 外鍵指向 User.user_id
    filename = db.Column(db.String(255), nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.Text, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # 定義與 User 的關係
    owner = db.relationship('User', backref='files')

# 文件共享表（對應 SQL 的 FileShare 表）
class FileShare(db.Model):
    __tablename__ = 'FileShare'
    share_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('File.file_id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('User.user_id'), nullable=False)
    permission_level = db.Column(db.String(10), default='read')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # 定義雙向外鍵關係
    file = db.relationship('File', backref='shares')
    shared_user = db.relationship('User', backref='shared_files')

# 審計日誌表（對應 SQL 的 AuditLog 表）
class AuditLog(db.Model):
    __tablename__ = 'AuditLog'
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.user_id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('File.file_id'))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    # 定義關係
    user = db.relationship('User', backref='audit_logs')
    file = db.relationship('File', backref='related_logs')