SET GLOBAL event_scheduler = ON;

DROP DATABASE IF EXISTS snh_db;
CREATE DATABASE snh_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create a local user that can only access the snh_db database
CREATE USER IF NOT EXISTS "snh_user"@"localhost" IDENTIFIED BY "super-strong-password";
ALTER USER "snh_user"@"localhost" IDENTIFIED BY "super-strong-password";
GRANT ALL PRIVILEGES ON snh_db.* TO "snh_user"@"localhost";

-- Apply changes
FLUSH PRIVILEGES;

USE snh_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role TINYINT NOT NULL DEFAULT 0,
    failed_login_attempts INT NOT NULL DEFAULT 0
);

CREATE TABLE pending_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL,
    timestamp DATETIME(0) NOT NULL DEFAULT NOW()
);

CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    timestamp DATETIME(0) NOT NULL,
    lyrics TEXT NOT NULL,
    audio LONGBLOB NOT NULL,
    premium TINYINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_posts_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE password_recovery (
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    timestamp DATETIME(0) NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_recovery_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE account_unlocking (
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    timestamp DATETIME(0) NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_unlocking_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- Account activation tokens are valid for 24 hours 

DELIMITER $$

CREATE EVENT IF NOT EXISTS flush_account_activation_tokens
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM pending_users
    WHERE timestamp < (NOW() - INTERVAL 24 HOUR);
END$$

-- Password recovery tokens are valid for 5 minutes

CREATE EVENT IF NOT EXISTS flush_password_recovery_tokens
ON SCHEDULE EVERY 1 MINUTE
DO
BEGIN
    DELETE FROM password_recovery
    WHERE timestamp < (NOW() - INTERVAL 5 MINUTE);
END$$

-- Account unlocking tokens are valid for 72 hours 

CREATE EVENT IF NOT EXISTS flush_account_unlocking_tokens
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM account_unlocking 
    WHERE timestamp < (NOW() - INTERVAL 72 HOUR);
END$$

DELIMITER ;

