alter table public.monitored_websites
  add column if not exists integration_method varchar(32) not null default 'generic_jsonl',
  add column if not exists collector_status varchar(16) not null default 'UNKNOWN',
  add column if not exists collector_last_seen_at timestamptz null,
  add column if not exists collector_last_error varchar(1000) not null default '',
  add column if not exists collector_last_error_at timestamptz null;
