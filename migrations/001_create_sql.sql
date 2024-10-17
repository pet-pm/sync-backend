-- Create the users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  avatar TEXT
);

-- Create the settings table
CREATE TABLE IF NOT EXISTS settings (
  userId TEXT PRIMARY KEY,
  sync_enabled BOOLEAN DEFAULT FALSE,
  proxy_url TEXT,
  FOREIGN KEY (userId) REFERENCES users(id)
);
