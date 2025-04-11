DROP DATABASE IF EXISTS online_storage;
CREATE DATABASE online_storage;
USE online_storage;

-- user table
CREATE TABLE User (
    user_id INT PRIMARY KEY AUTO_INCREMENT,       
    username VARCHAR(255) UNIQUE NOT NULL, 
    password_hash VARCHAR(255) NOT NULL,           -- use hashd password storage
    email VARCHAR(120) UNIQUE NOT NULL,            -- added email field
    otp VARCHAR(6),                                -- added OTP field
    otp_expiry DATETIME,                           -- added OTP expiry field
    salt VARCHAR(255),                            
    is_admin TINYINT(1) DEFAULT 0,               
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- file table
CREATE TABLE File (
    file_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,     
    -- Encryption parameters
    encrypted_content LONGBLOB NOT NULL,  -- Encrypted file content
    encrypted_key BLOB NOT NULL,  -- HMAC-SHA256(master_key, master_salt)
    file_salt BLOB NOT NULL,      -- 32-byte random
    master_salt BLOB NOT NULL,    -- 32-byte random
    iv BLOB NOT NULL,             -- 16-byte initialization vector
    file_size BIGINT NOT NULL,    -- Original file size in bytes
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- file sharing table
CREATE TABLE FileShare (
    share_id INT PRIMARY KEY AUTO_INCREMENT,
    file_id INT NOT NULL,
    shared_with_user_id INT NOT NULL,       
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES File(file_id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with_user_id) REFERENCES User(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- audit log table
CREATE TABLE AuditLog (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL,         
    file_id INT DEFAULT NULL,  
    details TEXT,                          -- additional details about the action                 
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User(user_id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES File(file_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- create indexes for performance optimization
CREATE INDEX idx_users_username ON User(username);
CREATE INDEX idx_files_user ON File(user_id);
CREATE INDEX idx_shares_file ON FileShare(file_id);
CREATE INDEX idx_audit_user ON AuditLog(user_id);

-- Insert admin user
-- Note: This uses a pre-hashed password for 'admin'
-- username: admin, password: 123
INSERT INTO User (username, email, password_hash, salt, is_admin, created_at) 
VALUES ('admin', 'admin@admin.com', '6a2741f1fe5609c8abc58d43936c7b9e017fa41c8e1bf2ba474aa7e3e07e784b:33b2f46fb4ecbc4a21ab6412e90c2db07e745cb304cf7d6c1d2139cdb48419a0:c75eda0e6b184526d98de675bfba44d479c3425a0e667c9bc4ebee3764acc35d','3??o???J!?d?-?~t\??}l!9ʹ??' , 1, CURRENT_TIMESTAMP);

-- Add audit log for admin creation
INSERT INTO AuditLog (user_id, action_type, details, timestamp)
VALUES (1, 'admin_create', 'Admin user created during database initialization', CURRENT_TIMESTAMP);