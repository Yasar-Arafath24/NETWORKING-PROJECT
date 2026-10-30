-- Repair tables created by an older/manual Supabase setup before indexes and app startup.

alter table public.analysis_reports
  add column if not exists owner_id bigint references public.users(id) on delete cascade;
alter table public.analysis_reports
  add column if not exists organization_id bigint references public.organizations(id) on delete cascade;
alter table public.analysis_reports
  add column if not exists filename varchar(512) not null default '';
alter table public.analysis_reports
  add column if not exists suspicious_flows integer not null default 0;

alter table public.live_flow_records
  add column if not exists owner_id bigint references public.users(id) on delete cascade;
alter table public.network_alerts
  add column if not exists owner_id bigint references public.users(id) on delete cascade;

alter table public.monitored_websites
  add column if not exists platform varchar(20) not null default 'custom';
alter table public.monitored_websites
  add column if not exists collector_revoked_at timestamptz;
alter table public.website_traffic_events
  add column if not exists request_timestamp timestamptz;

alter table public.users
  add column if not exists google_subject varchar(255);
alter table public.users
  add column if not exists email_verified boolean not null default true;
alter table public.users
  add column if not exists avatar_url text;
alter table public.users
  add column if not exists timezone varchar(64) not null default 'UTC';
alter table public.users
  add column if not exists last_login_at timestamptz;
alter table public.users
  add column if not exists updated_at timestamptz not null default now();

create unique index if not exists ix_users_google_subject
  on public.users(google_subject)
  where google_subject is not null;
