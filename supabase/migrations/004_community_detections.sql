-- Community shared detections
create table if not exists public.community_detections (
  id              uuid primary key default gen_random_uuid(),
  detection_id    text not null,
  user_id         uuid not null,
  author_name     text,
  name            text not null,
  query           text not null,
  tool            text,
  query_type      text,
  tactic          text,
  severity        text,
  threat          text,
  tags            text[],
  score           int default 0,
  stars           int default 0,
  clone_count     int default 0,
  is_public       boolean default true,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

alter table public.community_detections enable row level security;

-- Anyone can read public detections
create policy "public_read" on public.community_detections
  for select using (is_public = true);

-- Users can manage their own shared detections
create policy "owners_manage" on public.community_detections
  for all using (user_id = auth.uid())
  with check (user_id = auth.uid());

create index if not exists idx_community_public on public.community_detections(is_public, created_at desc);
create index if not exists idx_community_tactic on public.community_detections(tactic);
create index if not exists idx_community_tool on public.community_detections(tool);
create index if not exists idx_community_stars on public.community_detections(stars desc);
