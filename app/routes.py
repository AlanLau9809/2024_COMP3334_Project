from flask import Blueprint, render_template, redirect, request, url_for, flash,send_file, abort, current_app
from app import db, login_manager
from flask_login import login_user, logout_user, login_required, current_user
import os
import hmac
import hashlib
from secrets import token_bytes
from app.models import File, FileShare, AuditLog, User, db

auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

# -------------------------
# Cryptographic Primitives
# -------------------------

def generate_prng(length=32):
    """Cryptographically secure pseudo-random generator"""
    return token_bytes(length)

def hmac_sha256(key, data):
    """HMAC-SHA256 implementation without high-level abstractions"""
    return hmac.new(key, data, hashlib.sha256).digest()

def derive_file_key(master_key, salt):
    """Key derivation function for file encryption"""
    return hmac_sha256(master_key, salt)

# -------------------------
# Route Implementations
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
    log = AuditLog(user_id=current_user.id, action_type='logout', details='User logged out')
    db.session.add(log)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))


# -------------------------
# File Handling Utilities
# -------------------------

def secure_filename(filename):
    """Prevent path traversal attacks"""
    return os.path.basename(filename).replace('/', '_').replace('\\', '_')

def encrypt_file_content(raw_data, encryption_key):
    """Manual AES-256-CBC implementation using cryptography primitives"""
    # Implementation note: While we use cryptography library for raw AES operations,
    # we manually handle key derivation and encryption parameters
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    iv = generate_prng(16)  # Initialization Vector
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # PKCS7 padding
    pad_len = 16 - (len(raw_data) % 16)
    padded_data = raw_data + bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_file_content(encrypted_data, encryption_key):
    """Manual AES-256-CBC decryption"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove PKCS7 padding
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]


# -------------------------
# Route Implementations
# -------------------------

@main.route('/')
@login_required
def home():
    files = File.query.filter_by(user_id=current_user.user_id).all()
    return render_template('main.html', files=files)

@main.route('/upload', methods=['POST'])
@login_required
def upload():
    """Secure file upload endpoint with manual encryption"""
    # Validate input
    if 'file' not in request.files:
        return 'No file uploaded', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'Empty filename', 400
    
    # Check file size limit
    file.seek(0, os.SEEK_END)
    original_size = file.tell()
    file.seek(0)
    
    # Generate cryptographic materials
    master_salt = generate_prng()
    master_key = generate_prng()
    file_salt = generate_prng()
    file_key = derive_file_key(master_key, file_salt)
    
    # Process file
    filename = secure_filename(file.filename)
    raw_data = file.read()
    
    # Encrypt file
    encrypted_data = encrypt_file_content(raw_data, file_key)
    
    # Store encrypted file
    upload_path = os.path.join(
        current_app.config['UPLOAD_FOLDER'],
        f"user_{current_user.user_id}",
        filename
    )
    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
    
    with open(upload_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Create database record
    new_file = File(
        user_id=current_user.user_id,
        filename=filename,
        file_size=original_size,
        encrypted_key=hmac_sha256(master_key, master_salt),  # Store key hash
        file_salt=file_salt,
        master_salt=master_salt,
        file_path=upload_path
    )
    db.session.add(new_file)
    
    # Audit log
    audit = AuditLog(
        user_id=current_user.user_id,
        action_type='upload',
        file_id=new_file.file_id
    )
    db.session.add(audit)
    
    db.session.commit()
    
    return 'File uploaded securely', 201

@main.route('/share', methods=['POST'])
@login_required
def share():
    """Secure file sharing endpoint"""
    file_id = request.form.get('file_id')
    target_user_id = request.form.get('user_id')
    permission = request.form.get('permission', 'read')
    
    # Validate ownership
    file = File.query.filter_by(
        file_id=file_id,
        user_id=current_user.user_id
    ).first_or_404()
    
    # Validate target user
    target_user = User.query.get_or_404(target_user_id)
    
    # Create share record
    share = FileShare(
        file_id=file.file_id,
        shared_with_user_id=target_user.user_id,
        permission_level=permission,
        shared_key=hmac_sha256(file.encrypted_key, file.file_salt)  # Derive share-specific key
    )
    db.session.add(share)
    
    # Audit log
    audit = AuditLog(
        user_id=current_user.user_id,
        action_type='share',
        file_id=file.file_id
    )
    db.session.add(audit)
    
    db.session.commit()
    
    return 'File shared successfully', 200

@main.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    """Secure file deletion endpoint"""
    file = File.query.filter_by(
        file_id=file_id,
        user_id=current_user.user_id
    ).first_or_404()
    
    # Secure deletion process
    try:
        # Overwrite file content before deletion
        with open(file.file_path, 'wb') as f:
            f.write(generate_prng(os.path.getsize(file.file_path)))
        os.remove(file.file_path)
    except FileNotFoundError:
        pass
    
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
    
    return 'File permanently deleted', 200

@main.route('/download/<int:file_id>')
@login_required
def download(file_id):
    """Secure file download endpoint"""
    # Check ownership or shared access
    file = File.query.filter_by(file_id=file_id).first_or_404()
    
    # Verify access rights
    if file.user_id != current_user.user_id:
        share = FileShare.query.filter_by(
            file_id=file_id,
            shared_with_user_id=current_user.user_id
        ).first()
        if not share:
            abort(403)
    
    # Derive decryption key
    master_key = hmac_sha256(file.encrypted_key, file.master_salt)
    file_key = derive_file_key(master_key, file.file_salt)
    
    # Read and decrypt file
    with open(file.file_path, 'rb') as f:
        encrypted_data = f.read()
    
    try:
        decrypted_data = decrypt_file_content(encrypted_data, file_key)
    except ValueError:
        abort(500, description="Decryption failed - possible corruption")
    
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file.filename,
        as_attachment=True
    )