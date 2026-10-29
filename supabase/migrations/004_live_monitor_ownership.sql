alter table public.live_flow_records
  add column if not exists owner_id bigint references public.users(id) on delete cascade;
create index if not exists ix_live_flow_records_owner_id
  on public.live_flow_records(owner_id);

alter table public.network_alerts
  add column if not exists owner_id bigint references public.users(id) on delete cascade;
create index if not exists ix_network_alerts_owner_id
  on public.network_alerts(owner_id);
