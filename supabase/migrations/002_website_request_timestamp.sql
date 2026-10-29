alter table public.website_traffic_events
  add column if not exists request_timestamp timestamptz;
