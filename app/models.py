from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
# import HMAC_SHA256, PRNG

db = SQLAlchemy()

# 用戶表（對應 SQL 的 User 表）
class User(db.Model, UserMixin):   # 继承 UserMixin
    __tablename__ = 'User'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.SmallInteger, default=0)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        # salt = PRNG()
        # key = PRNG()
        # hash=HMAC_SHA256(key, password + salt)
        # library_sql.insert(userlist, (username, hash, salt))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_authenticated(self):
        return True  # 如果用户已通过验证返回 True
    
    @property
    def is_active(self):
        return True  # 如果账户是激活状态返回 True
    
    @property
    def is_anonymous(self):
        return False  # 普通用户返回 False
    
    def get_id(self):
        return str(self.user_id)  # 必须返回字符串类型的唯一标识

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
    owner = db.relationship('User', backref=db.backref('files', lazy='dynamic', cascade='all, delete-orphan'))

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