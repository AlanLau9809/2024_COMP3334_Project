import io
from flask import Blueprint, render_template, redirect, request, url_for, flash,send_file, abort, current_app
from app import db, login_manager
from flask_login import login_user, logout_user, login_required, current_user
import os
import hmac
import hashlib
from secrets import token_bytes
from app.models import File, FileShare, AuditLog, User, db

class FileSizeExceeded(Exception):
    pass

class InvalidFileType(Exception):
    pass


auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

# -------------------------
# Cryptographic Primitives (Revised)
# -------------------------

def generate_prng(length=32) -> bytes:
    """Generate cryptographically secure random bytes
    Args:
        length: Number of bytes to generate (default 32)
    Returns:
        Random bytes string
    """
    return os.urandom(length)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 implementation from scratch
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

def derive_file_key(master_key: bytes, salt: bytes) -> bytes:
    """Key derivation using HMAC-based KDF
    Args:
        master_key: Primary encryption key (32 bytes)
        salt: Random salt value (32 bytes)
    Returns:
        32-byte derived key
    """
    return hmac_sha256(master_key, salt)

# -------------------------
# Route Implementations
# -------------------------

# -------------------------
# Account Management Routes
# -------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username is already taken! Please choose another.', 'danger')
            return redirect(url_for('auth.register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log = AuditLog(
            user_id=new_user.user_id,
            action_type='register', 
            details='New user registration'
        )
        db.session.add(log)
        db.session.commit()

        flash('Account created successfully! You can now login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            logout_user()  # 安全终止会话
            flash('For security reasons, previous session was terminated', 'warning')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.home'))
        else:
            flash('Login failed. Check username and password.', 'danger')
    
    return render_template('login.html')


@auth.route('/logout')
@login_required
def logout():
    log = AuditLog(user_id=current_user.user_id, action_type='logout', details='User logged out')
    db.session.add(log)
    db.session.commit() 
    logout_user()
    return redirect(url_for('auth.login'))


# -------------------------
# File Encryption/Decryption (Revised)
# -------------------------

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_filename(filename):
    """Prevent path traversal attacks"""
    return os.path.basename(filename).replace('/', '_').replace('\\', '_')

def encrypt_file_content(raw_data, encryption_key):
    """AES-256 CBC encryption with proper IV handling"""
    iv = generate_prng(16)
    
    # 使用自己实现的AES加密，而不是库函数
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # PKCS7 padding
    pad_len = 16 - (len(raw_data) % 16)
    padded_data = raw_data + bytes([pad_len] * pad_len)
    
    # Encryption
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 返回IV + 密文，确保IV可以被正确提取
    return iv + ciphertext

def decrypt_file_content(encrypted_data, encryption_key):
    """AES-256 CBC decryption with validation"""
    # 提取IV（前16字节）
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Decryption
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 验证并移除PKCS7填充
    pad_len = padded_plaintext[-1]
    if not (1 <= pad_len <= 16):
        raise ValueError("Invalid padding length")
    if padded_plaintext[-pad_len:] != bytes([pad_len]*pad_len):
        raise ValueError("Invalid padding bytes")
    
    return padded_plaintext[:-pad_len]

# -------------------------
# ----------Main-----------
# -------------------------


# -------------------------
# Main Functionality Routes
# -------------------------

@main.route('/')
@login_required
def home():
    # 获取用户自己的文件
    own_files = File.query.filter_by(user_id=current_user.user_id).all()
    
    # 获取共享给当前用户的文件
    shared_files_query = db.session.query(File).\
        join(FileShare, File.file_id == FileShare.file_id).\
        filter(FileShare.shared_with_user_id == current_user.user_id)
    
    shared_files = shared_files_query.all()
    
    # 获取所有用户列表（用于共享对话框）
    all_users = User.query.filter(User.user_id != current_user.user_id).all()
    
    # 获取最近的审计日志
    recent_logs = AuditLog.query.filter_by(user_id=current_user.user_id).\
        order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('main.html', 
                          files=own_files, 
                          shared_files=shared_files,
                          all_users=all_users,
                          activity_logs=recent_logs)


# Route for setting profile settings, including password change
@main.route('/profile/settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        validation_passed = True
        
        # validate current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            validation_passed = False
        
        # validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            validation_passed = False

        # return and display error messages if validation failed
        if not validation_passed:
            return render_template('profile_settings.html')
        
        # additional validation for new password length
        try:
            current_user.set_password(new_password)
            audit = AuditLog(
                user_id=current_user.user_id,
                action_type='password_change',
                details='Password updated successfully'
            )
            db.session.add(audit)
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('main.home'))
        
        except Exception as e:
            db.session.rollback()
            flash('Password update failed. Please try again.', 'danger')
            return render_template('profile_settings.html')

    # GET request: render the profile settings page
    return render_template('profile_settings.html')

# For security reasons, we limit the maximum file size to 50MB
# This is to prevent denial of service attacks through large file uploads


@main.route('/upload', methods=['POST'])
@login_required
def upload():
    """Secure file upload with database storage"""
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('main.home'))
    
    file = request.files['file']
    if not file or file.filename == '':
        flash('Invalid filename', 'danger')
        return redirect(url_for('main.home'))
    
    try:
        # 安全文件名处理
        filename = secure_filename(file.filename)
        if not filename:
            raise ValueError("Invalid filename")
        
        # 文件验证
        if not allowed_file(filename):
            raise InvalidFileType()
        
        file.seek(0, os.SEEK_END)
        original_size = file.tell()
        if original_size > MAX_FILE_SIZE:
            raise FileSizeExceeded()
        file.seek(0)
        
        # 加密流程
        raw_data = file.read()
        
        # 生成加密材料
        master_salt = generate_prng(32)
        master_key = generate_prng(32)
        file_salt = generate_prng(32)
        file_key = derive_file_key(master_key, file_salt)
        
        # 加密文件
        encrypted_data = encrypt_file_content(raw_data, file_key)
        iv = encrypted_data[:16]  # 提取IV用于存储
        
        # 数据库存储
        new_file = File(
            user_id=current_user.user_id,
            filename=filename,
            encrypted_content=encrypted_data,  # 存储完整的加密数据（包含IV）
            encrypted_key=master_key,  # 直接存储主密钥，或者使用hmac_sha256加密
            file_salt=file_salt,
            master_salt=master_salt,
            iv=iv,
            file_size=original_size
        )
        
        db.session.add(new_file)
        
        # 添加审计日志
        log = AuditLog(
            user_id=current_user.user_id,
            action_type='upload',
            file_id=new_file.file_id,
            details=f'Uploaded file: {filename}'
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'"{filename}" encrypted and stored securely', 'success')
        return redirect(url_for('main.home'))
    
    except FileSizeExceeded:
        flash('File exceeds 50MB limit', 'danger')
    except InvalidFileType:
        flash('Unsupported file type', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Upload failed: {str(e)}', 'danger')
    
    return redirect(url_for('main.home'))


@main.route('/share', methods=['POST'])
@login_required
def share():
    """Secure file sharing endpoint"""
    file_id = request.form.get('file_id')
    target_users = request.form.getlist('users')  # 获取选中的用户ID列表
    permission = request.form.get('permission_level', 'read')
    
    if not file_id or not target_users:
        flash('Missing required information for sharing', 'danger')
        return redirect(url_for('main.home'))
    
    # 验证文件所有权
    file = File.query.filter_by(
        file_id=file_id,
        user_id=current_user.user_id
    ).first_or_404()
    
    success_count = 0
    
    for user_id in target_users:
        # 检查用户是否存在
        target_user = User.query.get(user_id)
        if not target_user:
            continue
            
        # 检查是否已经共享给该用户
        existing_share = FileShare.query.filter_by(
            file_id=file_id,
            shared_with_user_id=user_id
        ).first()
        
        if existing_share:
            # 更新现有共享的权限
            existing_share.permission_level = permission
        else:
            # 创建新的共享记录
            share = FileShare(
                file_id=file.file_id,
                shared_with_user_id=user_id,
                permission_level=permission
            )
            db.session.add(share)
        
        success_count += 1
    
    if success_count > 0:
        # 添加审计日志
        audit = AuditLog(
            user_id=current_user.user_id,
            action_type='share',
            file_id=file.file_id,
            details=f'Shared file with {success_count} users'
        )
        db.session.add(audit)
        db.session.commit()
        
        flash(f'File successfully shared with {success_count} users', 'success')
    else:
        flash('No users were selected or sharing failed', 'warning')
    
    return redirect(url_for('main.home'))

@main.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    """Secure file deletion endpoint"""
    try:
        file = File.query.filter_by(
            file_id=file_id,
            user_id=current_user.user_id
        ).first_or_404()
        
        filename = file.filename  # 获取文件名用于通知
        
        # Delete database records
        FileShare.query.filter_by(file_id=file_id).delete()
        db.session.delete(file)
        
        # Audit log
        audit = AuditLog(
            user_id=current_user.user_id,
            action_type='delete',
            file_id=file_id
        )
        db.session.add(audit)
        
        db.session.commit()
        
        flash(f'File "{filename}" has been permanently deleted', 'success')
    
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete file: {str(e)}', 'danger')
    
    return redirect(url_for('main.home'))

@main.route('/download/<int:file_id>')
@login_required
def download(file_id):
    # 获取文件记录
    file = File.query.filter_by(file_id=file_id).first_or_404()
    
    # 验证权限（文件所有者或共享用户）
    is_owner = file.user_id == current_user.user_id
    
    if not is_owner:
        # 检查是否有共享权限
        share = FileShare.query.filter_by(
            file_id=file_id, 
            shared_with_user_id=current_user.user_id
        ).first()
        
        if not share:
            abort(403, description="You don't have permission to access this file")
    
    try:
        # 密钥派生 - 确保与上传时使用相同的方法
        file_key = derive_file_key(file.encrypted_key, file.file_salt)
        
        # 解密流程
        encrypted_data = file.encrypted_content
        decrypted_data = decrypt_file_content(encrypted_data, file_key)
        
        # 记录下载操作
        log = AuditLog(
            user_id=current_user.user_id,
            action_type='download',
            file_id=file_id,
            details=f'Downloaded file: {file.filename}'
        )
        db.session.add(log)
        db.session.commit()
        
        # 发送文件
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file.filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    
    except Exception as e:
        db.session.rollback()
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('main.home'))
        abort(500, description=f"Decryption failed: {str(e)}")