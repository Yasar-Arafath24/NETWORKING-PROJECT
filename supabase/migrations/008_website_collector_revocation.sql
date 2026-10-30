alter table public.monitored_websites
  add column if not exists collector_revoked_at timestamptz null;
