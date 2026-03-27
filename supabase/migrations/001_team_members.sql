-- ── Team Members Table ────────────────────────────────────────────────────────
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)

create table if not exists public.team_members (
  id            uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null,          -- the user who owns/created the team
  member_email  text not null,
  member_name   text,
  member_user_id uuid,                  -- filled when invite is accepted
  role          text not null default 'Analyst'
                  check (role in ('Owner','Admin','Analyst','Read-only')),
  status        text not null default 'pending'
                  check (status in ('active','pending','removed')),
  team_name     text,
  invited_at    timestamptz not null default now(),
  joined_at     timestamptz,
  invite_token  text,
  constraint team_members_unique unique (owner_user_id, member_email)
);

-- ── Row Level Security ─────────────────────────────────────────────────────────
alter table public.team_members enable row level security;

-- Owners can see all members of their own team
create policy "owners_read_own_team"
  on public.team_members for select
  using (owner_user_id = auth.uid());

-- Members can see the team they belong to (by their email)
create policy "members_read_own_team"
  on public.team_members for select
  using (
    member_user_id = auth.uid()
    or member_email = (select email from auth.users where id = auth.uid())
  );

-- Only owners can insert/update/delete team members
create policy "owners_manage_team"
  on public.team_members for all
  using (owner_user_id = auth.uid())
  with check (owner_user_id = auth.uid());

-- Service role bypasses RLS (used by backend)
-- (service role key in env already bypasses RLS by default)

-- ── Detections Table RLS (if not already set) ─────────────────────────────────
-- Ensure detections table has RLS so users only see their own
alter table public.detections enable row level security;

create policy "users_own_detections" on public.detections
  for all using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- ── Autopilot Drafts Table RLS ────────────────────────────────────────────────
alter table public.autopilot_drafts enable row level security;

create policy "users_own_drafts" on public.autopilot_drafts
  for all using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- ── Index for fast team lookups ───────────────────────────────────────────────
create index if not exists idx_team_members_owner on public.team_members(owner_user_id);
create index if not exists idx_team_members_email on public.team_members(member_email);
create index if not exists idx_team_members_user  on public.team_members(member_user_id);
