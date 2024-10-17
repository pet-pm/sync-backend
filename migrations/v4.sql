-- Create the users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  avatar TEXT,
  password TEXT
);

-- Create the settings table (if you have one)
CREATE TABLE IF NOT EXISTS settings (
  userId TEXT PRIMARY KEY,
  sync_enabled BOOLEAN DEFAULT FALSE,
  proxy_url TEXT,
  FOREIGN KEY (userId) REFERENCES users(id)
);
