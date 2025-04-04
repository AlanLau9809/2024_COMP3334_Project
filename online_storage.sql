DROP DATABASE IF EXISTS online_storage;
CREATE DATABASE online_storage;
USE online_storage;

-- user table
CREATE TABLE User (
    user_id INT PRIMARY KEY AUTO_INCREMENT,       
    username VARCHAR(255) UNIQUE NOT NULL, 
    password_hash VARCHAR(255) NOT NULL,           -- use hashd password storage
    salt VARCHAR(255),                            
    is_admin TINYINT(1) DEFAULT 0,               
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- file table
CREATE TABLE File (
    file_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,           
    encrypted_key TEXT NOT NULL,               
    file_path TEXT NOT NULL,                    
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

-- 審計日誌表：記錄關鍵操作
CREATE TABLE AuditLog (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL,         
    file_id INT DEFAULT NULL,                   
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User(user_id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES File(file_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 創建索引優化查詢
CREATE INDEX idx_users_username ON User(username);
CREATE INDEX idx_files_user ON File(user_id);
CREATE INDEX idx_shares_file ON FileShare(file_id);
CREATE INDEX idx_audit_user ON AuditLog(user_id);