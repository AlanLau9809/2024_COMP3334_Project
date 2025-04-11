from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import os
import hashlib
from datetime import datetime

db = SQLAlchemy()

# Define encrytion tools
def generate_prng(length=32) -> bytes:
    """Generate cryptographically secure random bytes
    Args:
        length: Number of bytes to generate (default 32)
    Returns:
        Random bytes string
    """
    return os.urandom(length)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 implementation
    Args:
        key: Secret key (recommended 32 bytes)
        data: Data to authenticate
    Returns:
        32-byte HMAC digest
    """
    block_size = 64  # SHA-256 block size
    ipad = 0x36
    opad = 0x5C
    
    # Key processing
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block_size, b'\x00')
    
    # Inner padding
    i_key_pad = bytes([b ^ ipad for b in key])
    inner_hash = hashlib.sha256(i_key_pad + data).digest()
    
    # Outer padding
    o_key_pad = bytes([b ^ opad for b in key])
    return hashlib.sha256(o_key_pad + inner_hash).digest()

# users table
class User(db.Model, UserMixin):
    __tablename__ = 'User'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=True)  # Add salt column to store the salt
    email = db.Column(db.String(120), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.SmallInteger, default=0)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Define relationship with File
    files = db.relationship('File', backref='owner', foreign_keys='File.user_id')
    
    def set_password(self, password):
        """Set password using HMAC-SHA256 and PRNG"""
            
        # Generate a random salt
        salt = generate_prng(32)
        
        # Generate a key for HMAC
        key = generate_prng(32)
        
        # Create password hash using HMAC-SHA256
        password_bytes = password.encode('utf-8')
        hash_value = hmac_sha256(key, password_bytes + salt)
        
        # Store the salt, key, and hash in the database
        # Format: key:salt:hash (all hex encoded)
        self.salt = salt
        self.password_hash = key.hex() + ':' + salt.hex() + ':' + hash_value.hex()

    def check_password(self, password):
        """Verify password using HMAC-SHA256"""
        if not self.password_hash:
            return False
        
        # Split the stored hash into key, salt, and hash
        key_hex, salt_hex, stored_hash_hex = self.password_hash.split(':')
        
        # Convert hex strings back to bytes
        key = bytes.fromhex(key_hex)
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        
        # Verify the password
        password_bytes = password.encode('utf-8')
        hash_value = hmac_sha256(key, password_bytes + salt)
        
        return hash_value == stored_hash

    @property
    def is_administrator(self):
        return self.is_admin == 1
    
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

class File(db.Model):
    __tablename__ = 'File'  # Change to uppercase to match SQL schema
    file_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey('User.user_id', ondelete='CASCADE'),  # Change to match table name case
        nullable=False
    )
    filename = db.Column(db.String(255), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)  
    encrypted_key = db.Column(db.LargeBinary, nullable=False)
    file_salt = db.Column(db.LargeBinary, nullable=False)
    master_salt = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)  
    file_size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# file share table (for sharing files with other users)
class FileShare(db.Model):
    __tablename__ = 'FileShare'
    share_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('File.file_id', ondelete='CASCADE'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('User.user_id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Define relationships
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

    # Define relationships
    user = db.relationship('User', backref='audit_logs')
    file = db.relationship('File', backref='related_logs')