-- Create the users table with password column
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  avatar TEXT,
  password TEXT  -- New column for bcrypt-hashed password
);

-- Create the settings table
CREATE TABLE IF NOT EXISTS settings (
  userId TEXT PRIMARY KEY,
  sync_enabled BOOLEAN DEFAULT FALSE,
  proxy_url TEXT,
  FOREIGN KEY (userId) REFERENCES users(id)
);

-- Ensure the password column is added to the users table if it doesn't exist
ALTER TABLE users ADD COLUMN password TEXT;
