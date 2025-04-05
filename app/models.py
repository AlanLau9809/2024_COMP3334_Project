from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# TODO: implement HMAC_SHA256 and PRNG because the project required.
# import HMAC_SHA256, PRNG

db = SQLAlchemy()

# users table
class User(db.Model, UserMixin):   # 继承 UserMixin
    __tablename__ = 'User'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.SmallInteger, default=0)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
        # TODO: implement encryption password with HMAC_SHA256 and PRNG
        # salt = PRNG()
        # key = PRNG()
        # hash=HMAC_SHA256(key, password + salt)
        # library_sql.insert(userlist, (username, hash, salt))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_authenticated(self):
        return True  # if the user is authenticated, return True
    
    @property
    def is_active(self):
        return True  # if the user is active, return True
    
    @property
    def is_anonymous(self):
        return False  # normal users are not anonymous, return False
    
    def get_id(self):
        return str(self.user_id)  # make sure to return a string for user_id, as required by Flask-Login

# files table (for storing uploaded files)
class File(db.Model):
    __tablename__ = 'File'
    file_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.user_id'), nullable=False)  # foreign key to User table
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)
    file_salt = db.Column(db.LargeBinary, nullable=False)      # file-specific salt value for key derivation
    master_salt = db.Column(db.LargeBinary, nullable=False)    # master salt value for key derivation
    file_path = db.Column(db.Text, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # define relationship with User table
    owner = db.relationship('User', backref=db.backref('files', lazy='dynamic', cascade='all, delete-orphan'))

# file share table (for sharing files with other users)
class FileShare(db.Model):
    __tablename__ = 'FileShare'
    share_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('File.file_id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('User.user_id'), nullable=False)
    permission_level = db.Column(db.String(10), default='read')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # define relationships
    file = db.relationship('File', backref='shares')
    shared_user = db.relationship('User', backref='shared_files')

# audit log table (for tracking user actions)
class AuditLog(db.Model):
    __tablename__ = 'AuditLog'
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.user_id',ondelete='CASCADE'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('File.file_id'))
    details = db.Column(db.Text, nullable=True) 
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    # 定義關係
    user = db.relationship('User', backref='audit_logs')
    file = db.relationship('File', backref='related_logs')