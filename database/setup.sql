-- ============================================================
--  EventHub Database Setup
--  Run this on your Database VM as a MySQL root user:
--  mysql -u root -p < setup.sql
-- ============================================================

-- 1. Create the database
CREATE DATABASE IF NOT EXISTS eventhub_db;
USE eventhub_db;

-- 2. Create a dedicated app user (replace 'eventhub_password' with a strong password)
CREATE USER IF NOT EXISTS 'eventhub_user'@'%' IDENTIFIED BY 'eventhub_password';
GRANT ALL PRIVILEGES ON eventhub_db.* TO 'eventhub_user'@'%';
FLUSH PRIVILEGES;

-- 3. Users table
CREATE TABLE IF NOT EXISTS users (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  fullname    VARCHAR(120)  NOT NULL,
  email       VARCHAR(255)  NOT NULL UNIQUE,
  password    VARCHAR(255)  NOT NULL,          -- bcrypt hash
  role        ENUM('user', 'host', 'admin') NOT NULL DEFAULT 'user',
  created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Events table
CREATE TABLE IF NOT EXISTS events (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  title       VARCHAR(255)  NOT NULL,
  date        DATE          NOT NULL,
  location    VARCHAR(255)  NOT NULL,
  description TEXT          NOT NULL,
  createdBy   VARCHAR(255)  NOT NULL,          -- host's email
  created_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (createdBy) REFERENCES users(email) ON UPDATE CASCADE
);

-- 5. Seed one admin account
--    Password below is the bcrypt hash of "admin123" (12 salt rounds).
--    Change this immediately after first login!
INSERT IGNORE INTO users (fullname, email, password, role)
VALUES (
  'Site Admin',
  'admin@eventhub.com',
  '$2b$12$ePBBpFHLNr8OQXiNi8/5gOjl4vu2n2Fq0RQPQ.feFRlYVc3MzYGi',
  'admin'
);

-- ============================================================
--  MySQL remote access note:
--  In /etc/mysql/mysql.conf.d/mysqld.cnf, set:
--    bind-address = 0.0.0.0
--  Then restart MySQL:
--    sudo systemctl restart mysql
--  And allow the port in your firewall:
--    sudo ufw allow 3306
-- ============================================================
