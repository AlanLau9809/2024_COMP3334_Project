from datetime import datetime, timedelta
import io
import random
import string
from flask import Blueprint, jsonify, render_template, redirect, request,session, url_for, flash,send_file, abort, current_app
from flask_mail import Message
from sqlalchemy import asc, desc
from app import db, login_manager, mail
from flask_login import login_user, logout_user, login_required, current_user
import os,hmac,hashlib
from secrets import token_bytes
from app.models import File, FileShare, AuditLog, User, db

class FileSizeExceeded(Exception):
    pass

class InvalidFileType(Exception):
    pass


auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

# -------------------------
# Cryptographic Primitives
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

@auth.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    
    if not email or not username:
        return jsonify({'success': False, 'message': 'Email and username are required'})
    
    # 验证用户名和邮箱是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username is already taken'})
    
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email is already registered'})
    
    # 生成OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_expiry = datetime.now() + timedelta(minutes=10)
    
    # 将OTP存储在会话中
    session['registration_otp'] = {
        'email': email,
        'username': username,
        'otp': otp,
        'expiry': otp_expiry.timestamp()
    }
    
    # 发送OTP邮件
    try:
        msg = Message(
            'Your OTP Verification Code',
            sender=current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com'),
            recipients=[email]
        )
        msg.body = f'Your verification code is: {otp}\nThis code will expire in 10 minutes.'
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        otp = request.form.get('otp')
        
        # 验证密码是否匹配
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', username=username, email=email)
        
        # 验证用户名和邮箱是否已存在
        if User.query.filter_by(username=username).first():
            flash('Username is already taken', 'danger')
            return render_template('register.html', username='', email=email)
        
        if User.query.filter_by(email=email).first():
            flash('Email is already registered', 'danger')
            return render_template('register.html', username=username, email='')
        
        # 验证OTP
        registration_otp = session.get('registration_otp', {})
        stored_otp = registration_otp.get('otp')
        stored_email = registration_otp.get('email')
        stored_username = registration_otp.get('username')
        expiry = registration_otp.get('expiry', 0)
        
        if not stored_otp or email != stored_email or username != stored_username:
            flash('Please request a new verification code', 'danger')
            return render_template('register.html', username=username, email=email)
        
        if datetime.now().timestamp() > expiry:
            flash('Verification code has expired. Please request a new one', 'danger')
            return render_template('register.html', username=username, email=email)
        
        if otp != stored_otp:
            flash('Invalid verification code', 'danger')
            return render_template('register.html', username=username, email=email)
        
        # 创建新用户
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # 添加审计日志
        log = AuditLog(
            user_id=new_user.user_id,
            action_type='register',
            details='New user registration with email verification'
        )
        db.session.add(log)
        db.session.commit()
        
        # 清除会话中的OTP数据
        session.pop('registration_otp', None)
        
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


#--------------------------
#---------Admin------------
#--------------------------
@main.route('/admin/logs')
@login_required
def admin_logs():
    # Check if user is admin
    if not current_user.is_administrator:
        abort(403, "You don't have permission to access this page")
    
    # Get query parameters for filtering and sorting
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Logs per page
    
    username = request.args.get('username', '')
    action_type = request.args.get('action_type', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    sort = request.args.get('sort', 'timestamp')
    order = request.args.get('order', 'desc')
    
    # Build the query
    query = db.session.query(AuditLog).join(User, AuditLog.user_id == User.user_id)
    
    # Apply filters
    if username:
        query = query.filter(User.username.like(f'%{username}%'))
    
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d')
            # Add one day to include the end date
            to_date = to_date.replace(hour=23, minute=59, second=59)
            query = query.filter(AuditLog.timestamp <= to_date)
        except ValueError:
            pass
    
    # Apply sorting
    if sort == 'username':
        if order == 'asc':
            query = query.order_by(asc(User.username))
        else:
            query = query.order_by(desc(User.username))
    elif sort == 'action_type':
        if order == 'asc':
            query = query.order_by(asc(AuditLog.action_type))
        else:
            query = query.order_by(desc(AuditLog.action_type))
    elif sort == 'log_id':
        if order == 'asc':
            query = query.order_by(asc(AuditLog.log_id))
        else:
            query = query.order_by(desc(AuditLog.log_id))
    else:  # Default sort by timestamp
        if order == 'asc':
            query = query.order_by(asc(AuditLog.timestamp))
        else:
            query = query.order_by(desc(AuditLog.timestamp))
    
    # Paginate the results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    total_pages = pagination.pages
    
    # Prepare parameters for template
    next_order = 'asc' if order == 'desc' else 'desc'
    
    # Filter parameters for pagination links
    filter_params = {}
    if username:
        filter_params['username'] = username
    if action_type:
        filter_params['action_type'] = action_type
    if date_from:
        filter_params['date_from'] = date_from
    if date_to:
        filter_params['date_to'] = date_to
    
    return render_template(
        'admin_logs.html',
        logs=logs,
        page=page,
        total_pages=total_pages,
        sort=sort,
        order=order,
        next_order=next_order,
        filter_params=filter_params
    )
    


#--------------------------
#-----------User-----------
#--------------------------
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

@main.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    """允许文件所有者编辑文件内容"""
    # 获取文件并验证所有权
    file = File.query.filter_by(file_id=file_id).first_or_404()
    
    # 只有文件所有者可以编辑
    if file.user_id != current_user.user_id:
        flash('You do not have permission to edit this file', 'danger')
        return redirect(url_for('main.home'))
    
    # 检查文件类型是否可编辑
    editable_extensions = {'txt', 'md', 'html', 'css', 'js', 'json', 'xml', 'csv'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in editable_extensions:
        flash('This file type cannot be edited online', 'warning')
        return redirect(url_for('main.home'))
    
    try:
        # 解密文件内容
        file_key = derive_file_key(file.encrypted_key, file.file_salt)
        encrypted_data = file.encrypted_content
        decrypted_data = decrypt_file_content(encrypted_data, file_key)
        
        # 尝试将二进制内容转换为文本
        try:
            file_content = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            flash('This file contains binary data and cannot be edited online', 'warning')
            return redirect(url_for('main.home'))
        
        if request.method == 'POST':
            # 获取编辑后的内容
            new_content = request.form.get('content', '')
            
            # 加密新内容
            raw_data = new_content.encode('utf-8')
            encrypted_data = encrypt_file_content(raw_data, file_key)
            
            # 更新文件记录
            file.encrypted_content = encrypted_data
            file.file_size = len(raw_data)
            
            # 添加审计日志
            log = AuditLog(
                user_id=current_user.user_id,
                action_type='edit',
                file_id=file.file_id,
                details=f'Edited file: {file.filename}'
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'File "{file.filename}" has been updated', 'success')
            return redirect(url_for('main.home'))
        
        # GET 请求 - 显示编辑表单
        return render_template('edit_file.html', file=file, content=file_content)
    
    except Exception as e:
        flash(f'Error accessing file: {str(e)}', 'danger')
        return redirect(url_for('main.home'))

@main.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    """允许用户查看文件内容（不编辑）"""
    # 获取文件
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
    
    # 检查文件类型是否可查看
    viewable_extensions = {'txt', 'md', 'html', 'css', 'js', 'json', 'xml', 'csv'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in viewable_extensions:
        flash('This file type cannot be viewed online', 'warning')
        return redirect(url_for('main.home'))
    
    try:
        # 解密文件内容
        file_key = derive_file_key(file.encrypted_key, file.file_salt)
        encrypted_data = file.encrypted_content
        decrypted_data = decrypt_file_content(encrypted_data, file_key)
        
        # 尝试将二进制内容转换为文本
        try:
            file_content = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            flash('This file contains binary data and cannot be viewed online', 'warning')
            return redirect(url_for('main.home'))
        
        # 记录查看操作
        log = AuditLog(
            user_id=current_user.user_id,
            action_type='view',
            file_id=file_id,
            details=f'Viewed file: {file.filename}'
        )
        db.session.add(log)
        db.session.commit()
        
        # 显示文件内容
        return render_template('view_file.html', file=file, content=file_content, is_owner=is_owner)
    
    except Exception as e:
        flash(f'Error viewing file: {str(e)}', 'danger')
        return redirect(url_for('main.home'))

# Add these fields to your User model
otp = db.Column(db.String(6), nullable=True)
otp_expiry = db.Column(db.DateTime, nullable=True)
email = db.Column(db.String(120), unique=True, nullable=False)
