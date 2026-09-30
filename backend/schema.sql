PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('login_failed','login_success','role_changed','session_ended')),
  account TEXT NOT NULL,
  ip TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('user','admin')),
  source TEXT NOT NULL CHECK(source = 'identity-lab')
);
CREATE INDEX IF NOT EXISTS idx_events_account_time ON events(account, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
