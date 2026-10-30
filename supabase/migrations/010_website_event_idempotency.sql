alter table public.website_traffic_events
  add column if not exists event_id varchar(128) null;

create unique index if not exists uq_website_events_site_event_id
  on public.website_traffic_events (site_id, event_id);
