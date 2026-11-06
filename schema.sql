-- schema.sql (updated for secure password hashing)
-- Run this on a fresh disposable local MySQL instance only.
-- After importing, create test accounts via the Register form
-- so passwords are stored with bcrypt (password_hash).

CREATE DATABASE IF NOT EXISTS notes_lab CHARACTER SET utf8mb4;
USE notes_lab;

CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email         VARCHAR(254) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(20)  NOT NULL DEFAULT 'student'
);

CREATE TABLE IF NOT EXISTS notes (
  id      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  title   VARCHAR(120) NOT NULL,
  body    TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- NOTE: The original MD5 seed accounts have been removed.
-- The repaired code uses password_hash() / password_verify() (bcrypt).
-- MD5 hashes are NOT compatible with password_verify(), so the old
-- INSERT rows would break login.
--
-- After importing this schema, start the PHP server and register
-- fresh synthetic accounts through the web UI:
--   alex@example.test  /  LabOnly-Alex-123
--   sam@example.test   /  LabOnly-Sam-456
-- Then add notes through the app.  Document the new test setup in your report.
