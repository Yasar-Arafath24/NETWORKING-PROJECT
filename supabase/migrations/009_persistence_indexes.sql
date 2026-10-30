-- Persistence completeness and lookup indexes for all application data.
-- Apply after migrations 001-008.

create index if not exists ix_analysis_reports_owner_created
  on public.analysis_reports (owner_id, created_at desc);

create index if not exists ix_live_flow_records_owner_updated
  on public.live_flow_records (owner_id, last_updated desc);

create index if not exists ix_network_alerts_owner_created
  on public.network_alerts (owner_id, created_at desc);

create index if not exists ix_monitored_websites_owner_created
  on public.monitored_websites (owner_id, created_at desc);

create index if not exists ix_website_traffic_events_site_timestamp
  on public.website_traffic_events (site_id, request_timestamp desc);

-- Sensitive application tables are backend-service-role only.
revoke all on table public.live_flow_records, public.network_alerts
  from anon, authenticated;
revoke all on table public.monitored_websites, public.website_traffic_events
  from anon, authenticated;
