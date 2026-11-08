CREATE TABLE IF NOT EXISTS veridict_scan_quotas (
  quota_key text PRIMARY KEY,
  minute_window_started_at timestamptz NOT NULL,
  minute_count integer NOT NULL DEFAULT 0,
  daily_window_started_at timestamptz NOT NULL,
  daily_count integer NOT NULL DEFAULT 0,
  lifetime_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);
