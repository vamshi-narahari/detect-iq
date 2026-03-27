create table if not exists public.siem_push_audit (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid,
  detection_id text,
  detection_name text,
  platform     text not null,
  status       text not null check (status in ('success','failure')),
  message      text,
  ip_address   text,
  created_at   timestamptz not null default now()
);

alter table public.siem_push_audit enable row level security;

create policy "users_read_own_audit" on public.siem_push_audit
  for select using (user_id = auth.uid());

create policy "service_insert_audit" on public.siem_push_audit
  for insert with check (true);

create index if not exists idx_audit_user on public.siem_push_audit(user_id);
create index if not exists idx_audit_platform on public.siem_push_audit(platform);
create index if not exists idx_audit_created on public.siem_push_audit(created_at desc);
