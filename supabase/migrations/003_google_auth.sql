alter table public.users
  add column if not exists google_subject varchar(255);

create unique index if not exists ix_users_google_subject
  on public.users (google_subject);
