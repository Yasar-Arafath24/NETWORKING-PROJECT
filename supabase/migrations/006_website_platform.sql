alter table public.monitored_websites
  add column if not exists platform varchar(20) not null default 'custom';
