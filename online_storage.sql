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
    permission_level VARCHAR(10) DEFAULT 'read', 
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
-- Note: This uses a pre-hashed password for '123'
INSERT INTO User (username, email, password_hash, is_admin, created_at) 
VALUES ('admin', 'admin@admin.com', 'scrypt:32768:8:1$ePaVRqlMtWYtlqY4$a99fd8bb9ac9d2b1b8db9f377fe05a95fc874425bf5030ffaa9e430d82e4486ed7a3f222720a914f1d66e4e3959b857129d2a6e68e8bf297de8e2576e263cb2f', 1, CURRENT_TIMESTAMP);

-- Add audit log for admin creation
INSERT INTO AuditLog (user_id, action_type, details, timestamp)
VALUES (1, 'admin_create', 'Admin user created during database initialization', CURRENT_TIMESTAMP);