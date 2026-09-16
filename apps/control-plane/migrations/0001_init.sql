PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  serial_number TEXT NOT NULL UNIQUE,
  agent_token TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  enrolled_at TEXT NOT NULL,
  last_seen_at TEXT,
  health_json TEXT
);

CREATE TABLE IF NOT EXISTS payment_periods (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(id),
  sequence INTEGER NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  currency TEXT NOT NULL CHECK(length(currency) = 3),
  due_on TEXT NOT NULL,
  paid_at TEXT,
  UNIQUE(device_id, sequence)
);

CREATE TABLE IF NOT EXISTS commands (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  claimed_at TEXT,
  completed_at TEXT,
  result TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commands_pending ON commands(device_id, completed_at, created_at);
CREATE INDEX IF NOT EXISTS idx_payments_device ON payment_periods(device_id, sequence);

