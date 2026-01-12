-- Enhanced Users table with security features
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) UNIQUE NOT NULL,
    Email VARCHAR(100) UNIQUE NOT NULL,
    PasswordHash VARCHAR(255) NOT NULL,
    Salt VARCHAR(255) NOT NULL,
    Role VARCHAR(50) DEFAULT 'user',
    IsActive BOOLEAN DEFAULT TRUE,
    FailedLoginAttempts INT DEFAULT 0,
    LastLogin DATETIME,
    AccountLockedUntil DATETIME,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (Username),
    INDEX idx_email (Email),
    INDEX idx_role (Role)
);

-- Create sessions table for secure session management
CREATE TABLE UserSessions (
    SessionID VARCHAR(255) PRIMARY KEY,
    UserID INT NOT NULL,
    Token VARCHAR(255) NOT NULL,
    IPAddress VARCHAR(45),
    UserAgent TEXT,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    ExpiresAt DATETIME NOT NULL,
    IsValid BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE,
    INDEX idx_token (Token),
    INDEX idx_user_expires (UserID, ExpiresAt)
);

-- Create audit log for security monitoring
CREATE TABLE AuditLog (
    LogID INT PRIMARY KEY AUTO_INCREMENT,
    UserID INT,
    Action VARCHAR(100) NOT NULL,
    Description TEXT,
    IPAddress VARCHAR(45),
    UserAgent TEXT,
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE SET NULL,
    INDEX idx_user_timestamp (UserID, Timestamp),
    INDEX idx_action_timestamp (Action, Timestamp)
);