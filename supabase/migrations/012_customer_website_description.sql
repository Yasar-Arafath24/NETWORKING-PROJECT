alter table public.monitored_websites
  add column if not exists description varchar(1000) not null default '';
