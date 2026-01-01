# COMP3334 - Computer Systems Security Group Project (2024)
## Secure Online Storage System with Client-Side Encryption

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.2-green.svg)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-AES--256--CBC-red.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![License](https://img.shields.io/badge/License-Academic-yellow.svg)](LICENSE)

## 📋 Abstract

This project implements a **secure online storage system** designed to protect user data from passive attacks through comprehensive security measures. The system features **client-side file encryption**, **multi-factor authentication**, **secure password hashing**, and **comprehensive audit logging**. The design ensures that server administrators cannot access unencrypted files while maintaining usability and implementing defense against common security vulnerabilities.

**Key Security Focus**: Protection against passive adversaries including server operators and unauthorized users attempting to decrypt data or compromise accounts.

## 🔒 Security Architecture

### Threat Model
- **Server Operators**: Passive adversaries who can read encrypted files and observe client-server communications but cannot perform active attacks
- **Unauthorized Users**: Malicious actors with compromised devices or stolen credentials attempting to access or decrypt user data

### Core Security Features
- **🔐 AES-256-CBC Encryption** with unique initialization vectors (IV)
- **🔑 HMAC-SHA256** for secure password hashing and key derivation
- **📧 Multi-Factor Authentication** via email OTP verification
- **🛡️ SQL Injection Protection** using SQLAlchemy ORM
- **📊 Comprehensive Audit Logging** for all user actions
- **🚫 Access Control** with file ownership and sharing permissions

## 🏗️ Technical Implementation

### Encryption Algorithms
```
File Encryption: AES-256-CBC with PKCS#7 Padding
Key Derivation: HMAC-based Key Derivation Function (HKDF)
Password Hashing: HMAC-SHA256 with cryptographically secure salt
Random Generation: os.urandom() for cryptographically secure randomness
```

### Security Measures
- **Client-side encryption** before file upload
- **Unique encryption keys** per file with secure key derivation
- **Session management** with secure cookie configuration
- **Input validation** and sanitization
- **Role-based access control** (User/Admin)

## 🚀 Features

### User Management
- ✅ Secure user registration with email verification
- ✅ Multi-factor authentication (OTP via email)
- ✅ Password strength validation and secure storage
- ✅ Session management with automatic logout

### File Operations
- ✅ **Encrypted file upload** (supports .txt, .pdf, .docx, .xlsx, .pptx, images, audio, video, archives)
- ✅ **Secure file sharing** with permission controls
- ✅ **Online file viewing/editing** for text files
- ✅ **Encrypted file download** with integrity verification
- ✅ **Secure file deletion** with database cleanup

### Administrative Features
- ✅ **Comprehensive audit logging** with filtering and search
- ✅ **User activity monitoring** and suspicious behavior detection
- ✅ **System-wide security oversight** and access control management

### Security Validations
- ✅ **SQL Injection Protection** - Demonstrated resistance to injection attacks
- ✅ **Unauthorized Access Prevention** - Session-based access control
- ✅ **Admin Privilege Escalation Protection** - Role verification for sensitive operations

## 📋 Requirements

### System Requirements
- **Python**: 3.9 or higher
- **Database**: MySQL 8.0+ or MariaDB 10.5+
- **Web Server**: Development server included (Flask)
- **Email Service**: SMTP server for OTP delivery

### Python Dependencies
```
flask==3.0.2
flask-sqlalchemy==3.1.1
flask-login==0.6.3
flask-migrate==4.0.5
cryptography==42.0.5
python-dotenv==1.0.1
pymysql==1.1.0
wtforms==3.1.2
flask-mail==0.10.0
```

## 🛠️ Installation & Setup

### 1. Clone Repository
```bash
git clone https://github.com/AlanLau9809/COMP3334_Project.git
cd COMP3334_Project
```

### 2. Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup

#### Option A: Using XAMPP (Recommended for Development)
1. **Install and start XAMPP**
2. **Start MySQL service** in XAMPP Control Panel
3. **Import database schema**:
   - Open phpMyAdmin (http://localhost/phpmyadmin)
   - Create new database or import `online_storage.sql`

#### Option B: Manual MySQL Setup
```bash
# Login to MySQL
mysql -u root -p

# Create database
CREATE DATABASE online_storage;

# Import schema
mysql -u root -p online_storage < online_storage.sql
```

### 5. Email Configuration (Required for OTP)
The system uses Gmail SMTP for OTP delivery. Current configuration in `app/__init__.py`:
```python
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'polycomp3334project@gmail.com'
app.config['MAIL_PASSWORD'] = 'ibby erqs ekoa lqtj'  # App-specific password
```

**For production deployment**: Update email credentials in `app/__init__.py` or use environment variables.

### 6. Run Application
```bash
python run.py
```

**Access the application**: [http://localhost:5000](http://localhost:5000)

## 👤 Default Admin Account

A pre-configured admin account is included for initial setup:

```
Username: admin
Password: 123
Email: admin@admin.com
```

**⚠️ Security Notice**: 
- Change the default password immediately after first login
- This account should only be used for initial system setup
- Create additional admin accounts through database modification if needed

### Creating Additional Admin Users
```sql
-- Method 1: Promote existing user to admin
UPDATE User SET is_admin = 1 WHERE username = 'your_username';

-- Method 2: Verify admin status
SELECT username, is_admin FROM User WHERE is_admin = 1;
```

## 🔍 Security Testing & Validation

### SQL Injection Protection Test
The system successfully prevents SQL injection attacks through SQLAlchemy ORM:
```
✅ Parameterized queries prevent injection
✅ Input sanitization and validation
✅ No raw SQL query execution
```

### Access Control Validation
```
✅ Session-based authentication required
✅ File ownership verification
✅ Admin privilege verification for sensitive operations
✅ Automatic session termination for security
```

### Encryption Validation
```
✅ Unique encryption keys per file
✅ Secure key derivation using HMAC
✅ Proper IV generation and handling
✅ PKCS#7 padding implementation
```

## 📊 System Architecture

### Database Schema
- **User**: User accounts with secure password storage
- **File**: Encrypted file storage with metadata
- **FileShare**: File sharing permissions and access control
- **AuditLog**: Comprehensive activity logging

### Security Flow
1. **User Registration** → Email OTP verification → Secure password hashing
2. **File Upload** → Client-side encryption → Secure key storage
3. **File Access** → Permission verification → Decryption → Audit logging
4. **Admin Operations** → Role verification → Action logging

## 🔮 Future Enhancements

### Planned Security Improvements
- **Version Control**: Encrypted file versioning with delta encoding
- **Trash & Recovery**: 30-day encrypted file recovery system
- **Advanced Sharing**: Time-limited access and read-only permissions
- **Notification System**: Security alerts for failed login attempts
- **API Development**: RESTful API for third-party integrations

### Technical Roadmap
- **Enhanced Encryption**: Consider post-quantum cryptography
- **Zero-Knowledge Architecture**: Server-side encryption key elimination
- **Advanced Audit**: Machine learning for anomaly detection
- **Mobile Support**: Cross-platform mobile application

## 🏆 Project Achievements

### Security Implementation
- ✅ **Zero server-side plaintext exposure** - All files encrypted before upload
- ✅ **Comprehensive threat mitigation** - Protection against passive adversaries
- ✅ **Industry-standard cryptography** - AES-256-CBC with proper implementation
- ✅ **Multi-layered security** - Authentication, authorization, and audit logging

### Technical Excellence
- ✅ **Clean architecture** - Separation of concerns with Flask blueprints
- ✅ **Secure coding practices** - Input validation, error handling, session management
- ✅ **Database security** - ORM usage, proper indexing, foreign key constraints
- ✅ **User experience** - Intuitive interface with security transparency

## 📚 Technical References

### Cryptographic Standards
- [NIST AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [RFC 2104 - HMAC](https://tools.ietf.org/html/rfc2104)
- [PKCS #7 Padding](https://tools.ietf.org/html/rfc2315)

### Security Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Guidelines](https://flask.palletsprojects.com/en/stable/security/)
- [Python Cryptography Documentation](https://cryptography.io/)

## 📄 License

This project is developed for academic purposes as part of COMP3334 - Computer Systems Security course. All rights reserved for educational use.

---

**Developed by**: COMP3334 Group Project Team  
**Course**: Computer Systems Security (2024)  
**Institution**: The Hong Kong Polytechnic University  
**Focus**: Secure system design and implementation against passive adversaries
