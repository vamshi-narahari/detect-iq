create table if not exists public.detection_versions (
  id            uuid primary key default gen_random_uuid(),
  detection_id  uuid not null,
  user_id       uuid not null,
  name          text,
  query         text,
  notes         text,
  created_at    timestamptz not null default now()
);

alter table public.detection_versions enable row level security;

create policy "users_own_versions" on public.detection_versions
  for all using (user_id = auth.uid())
  with check (user_id = auth.uid());

create index if not exists idx_versions_detection on public.detection_versions(detection_id);
create index if not exists idx_versions_user on public.detection_versions(user_id);
