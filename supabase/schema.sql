-- DetectIQ schema. Idempotent — safe to re-run in the Supabase SQL editor.
create extension if not exists "uuid-ossp";

-- ============ DETECTIONS ============
create table if not exists public.detections (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  name text not null,
  query text not null,
  tool text not null,               -- 'splunk' | 'crowdstrike' | 'logscale' | 'sentinel' | ...
  tactic text,
  technique_id text,                -- e.g. T1059.001
  severity text,
  description text,
  status text default 'draft',      -- 'draft' | 'active' | 'disabled'
  source text default 'manual',     -- 'manual' | 'ai'
  tags text[],
  score integer default 0,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
alter table public.detections enable row level security;

drop policy if exists "detections_select_own" on public.detections;
create policy "detections_select_own" on public.detections for select using (auth.uid() = user_id);
drop policy if exists "detections_insert_own" on public.detections;
create policy "detections_insert_own" on public.detections for insert with check (auth.uid() = user_id);
drop policy if exists "detections_update_own" on public.detections;
create policy "detections_update_own" on public.detections for update using (auth.uid() = user_id);
drop policy if exists "detections_delete_own" on public.detections;
create policy "detections_delete_own" on public.detections for delete using (auth.uid() = user_id);

-- ============ SUPPRESSION RULES (Allowlists) ============
-- Unified allowlist/threshold model. scope='global' applies everywhere;
-- scope='detection' applies only to detection_id. destination scopes a row
-- to one SIEM or 'all'. target_mechanism records how it compiles per-SIEM.
create table if not exists public.suppression_rules (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  detection_id uuid references public.detections(id) on delete cascade,
  scope text default 'detection', -- 'global' | 'detection'
  field text not null,
  op text default 'equals', -- 'equals' | 'contains' | 'cidr'
  value text not null,
  reason text,
  destination text default 'all', -- 'all' | 'splunk' | 'crowdstrike' | 'logscale' | 'sentinel' | ...
  target_mechanism text default 'internal', -- 'splunk_lookup' | 'native_exclusion' | 'internal'
  expires_at timestamptz,
  created_at timestamptz default now()
);
alter table public.suppression_rules enable row level security;
alter table public.suppression_rules alter column detection_id drop not null;
alter table public.suppression_rules add column if not exists scope text default 'detection';
alter table public.suppression_rules add column if not exists op text default 'equals';
alter table public.suppression_rules add column if not exists destination text default 'all';

drop policy if exists "suppression_select_own" on public.suppression_rules;
create policy "suppression_select_own" on public.suppression_rules for select using (auth.uid() = user_id);
drop policy if exists "suppression_insert_own" on public.suppression_rules;
create policy "suppression_insert_own" on public.suppression_rules for insert with check (auth.uid() = user_id);
drop policy if exists "suppression_update_own" on public.suppression_rules;
create policy "suppression_update_own" on public.suppression_rules for update using (auth.uid() = user_id);
drop policy if exists "suppression_delete_own" on public.suppression_rules;
create policy "suppression_delete_own" on public.suppression_rules for delete using (auth.uid() = user_id);

-- ============ VALIDATION RUNS ============
create table if not exists public.validation_runs (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  detection_id uuid references public.detections(id) on delete cascade not null,
  method text not null,              -- 'synthetic' | 'safebreach' | 'atomic_red_team'
  status text default 'queued',      -- 'queued' | 'running' | 'passed' | 'failed'
  fired boolean,
  noise_events integer default 0,
  notes text,
  started_at timestamptz default now(),
  finished_at timestamptz
);
alter table public.validation_runs enable row level security;

drop policy if exists "validation_select_own" on public.validation_runs;
create policy "validation_select_own" on public.validation_runs for select using (auth.uid() = user_id);
drop policy if exists "validation_insert_own" on public.validation_runs;
create policy "validation_insert_own" on public.validation_runs for insert with check (auth.uid() = user_id);
drop policy if exists "validation_update_own" on public.validation_runs;
create policy "validation_update_own" on public.validation_runs for update using (auth.uid() = user_id);

-- ============ INTEGRATIONS ============
create table if not exists public.integrations (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  provider text not null,            -- 'splunk' | 'crowdstrike' | 'safebreach' | ...
  category text not null,            -- 'siem' | 'simulation'
  status text default 'disconnected',-- 'connected' | 'disconnected'
  config jsonb default '{}'::jsonb,
  created_at timestamptz default now(),
  unique (user_id, provider)
);
alter table public.integrations enable row level security;

drop policy if exists "integrations_all_own" on public.integrations;
create policy "integrations_all_own" on public.integrations for all using (auth.uid() = user_id);

-- ============ PACKS (ATT&CK technique groups) ============
-- A pack does not run itself — it's a grouping of techniques you want
-- correlated coverage on. Coverage is computed by matching detections'
-- technique_id against a pack's techniques array.
create table if not exists public.packs (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  name text not null,
  description text,
  techniques text[] default '{}',
  created_at timestamptz default now()
);
alter table public.packs enable row level security;
drop policy if exists "packs_all_own" on public.packs;
create policy "packs_all_own" on public.packs for all using (auth.uid() = user_id);

-- ============ MACROS ============
create table if not exists public.macros (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade,
  name text not null,
  kind text not null, -- 'allowlist' | 'enrich' | 'emit' | 'parse' | 'normalize'
  description text,
  query_body text default '',
  is_system boolean default false,
  created_at timestamptz default now()
);
alter table public.macros enable row level security;
drop policy if exists "macros_select_all" on public.macros;
create policy "macros_select_all" on public.macros for select using (is_system = true or auth.uid() = user_id);
drop policy if exists "macros_insert_own" on public.macros;
create policy "macros_insert_own" on public.macros for insert with check (auth.uid() = user_id);
drop policy if exists "macros_update_own" on public.macros;
create policy "macros_update_own" on public.macros for update using (auth.uid() = user_id);
drop policy if exists "macros_delete_own" on public.macros;
create policy "macros_delete_own" on public.macros for delete using (auth.uid() = user_id);

insert into public.macros (name, kind, description, is_system)
select * from (values
  ('detectiq_allow_admin_tools', 'allowlist', 'Drop expected IT/EDR/admin parent processes.', true),
  ('detectiq_allow_it_paths', 'allowlist', 'Drop binaries launched from known IT/Program Files paths.', true),
  ('detectiq_allow_service_accounts', 'allowlist', 'Drop known service/scanner accounts.', true),
  ('detectiq_emit_index', 'emit', 'Write normalized notable fields into the detections index.', true),
  ('detectiq_enrich_asset', 'enrich', 'Asset lookup placeholder — swap for your CMDB lookup.', true)
) as t(name, kind, description, is_system)
where not exists (select 1 from public.macros where is_system = true);

-- ============ INTAKE REQUESTS ============
create table if not exists public.intake_requests (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  title text not null,
  notes text,
  priority text default 'medium',
  technique_id text,
  source text default 'manual', -- 'manual' | 'jira' | 'outlook' | 'teams' | 'webex' | 'webhook' | 'gap' | 'builder'
  status text default 'open',   -- 'open' | 'building' | 'review' | 'done'
  detection_id uuid references public.detections(id),
  external_id text,
  created_at timestamptz default now()
);
alter table public.intake_requests enable row level security;
alter table public.intake_requests add column if not exists external_id text;
drop policy if exists "intake_all_own" on public.intake_requests;
create policy "intake_all_own" on public.intake_requests for all using (auth.uid() = user_id);

-- ============ DETECTION DEPLOYMENT / VALIDATION FIELDS ============
alter table public.detections add column if not exists schedule_cron text default '*/15 * * * *';
alter table public.detections add column if not exists threshold integer default 1;
alter table public.detections add column if not exists alert_actions text[] default '{}';
alter table public.detections add column if not exists saved_search_name text;
alter table public.detections add column if not exists validation_status text default 'unvalidated'; -- 'unvalidated' | 'ai_sample_tested' | 'agent_tested' | 'simulated'
alter table public.detections add column if not exists validated_at timestamptz;
alter table public.detections add column if not exists tuning_notes text;
alter table public.detections add column if not exists false_positives text;

alter table public.validation_runs add column if not exists output text;

-- ============ PER-DETECTION ENRICHMENT (post-alert lookups) ============
create table if not exists public.detection_enrichments (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  detection_id uuid references public.detections(id) on delete cascade not null,
  provider text not null, -- 'virustotal' | 'abuseipdb' | 'shodan' | 'urlscan'
  field text not null,    -- e.g. 'src_ip', 'file_hash', 'url'
  enabled boolean default true,
  created_at timestamptz default now()
);
alter table public.detection_enrichments enable row level security;
drop policy if exists "enrichments_all_own" on public.detection_enrichments;
create policy "enrichments_all_own" on public.detection_enrichments for all using (auth.uid() = user_id);

-- ============ USER PROFILES (avatar + timezone) ============
create table if not exists public.profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  timezone text default 'UTC',
  avatar_url text,
  updated_at timestamptz default now()
);
alter table public.profiles enable row level security;
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles for select using (auth.uid() = id);
drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own" on public.profiles for insert with check (auth.uid() = id);
drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles for update using (auth.uid() = id);

-- Before these storage policies do anything, create a PUBLIC bucket named
-- "avatars" in the Supabase dashboard: Storage → New bucket → name "avatars",
-- toggle Public on. Then these policies let each user manage only their own
-- folder (avatars/<user_id>/...) while anyone can view any avatar.
drop policy if exists "avatar_public_read" on storage.objects;
create policy "avatar_public_read" on storage.objects for select using (bucket_id = 'avatars');
drop policy if exists "avatar_owner_write" on storage.objects;
create policy "avatar_owner_write" on storage.objects for insert with check (bucket_id = 'avatars' and auth.uid()::text = (storage.foldername(name))[1]);
drop policy if exists "avatar_owner_update" on storage.objects;
create policy "avatar_owner_update" on storage.objects for update using (bucket_id = 'avatars' and auth.uid()::text = (storage.foldername(name))[1]);

-- ============ ASSETS (for macros/enrichment to reference) ============
create table if not exists public.assets (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  name text not null,
  type text default 'host', -- 'host' | 'service_account' | 'cloud_resource' | 'other'
  owner text,
  criticality text default 'medium', -- 'low' | 'medium' | 'high' | 'critical'
  tags text[] default '{}',
  notes text,
  created_at timestamptz default now()
);
alter table public.assets enable row level security;
drop policy if exists "assets_all_own" on public.assets;
create policy "assets_all_own" on public.assets for all using (auth.uid() = user_id);

-- ============ BLINDSPOT AGENT FINDINGS ============
-- Persisted, individually-trackable findings from Blindspot Agent runs —
-- not just a one-off report dumped into validation_runs. run_id groups
-- findings from the same run (single-detection or batch scan) together.
create table if not exists public.blindspot_findings (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  detection_id uuid references public.detections(id) on delete cascade not null,
  run_id uuid not null,
  name text not null,
  description text,
  evasion_sample text,
  suggested_patch text,
  severity text default 'medium', -- 'low' | 'medium' | 'high' | 'critical'
  status text default 'open',     -- 'open' | 'patched' | 'dismissed'
  dismissal_reason text,
  created_at timestamptz default now()
);
alter table public.blindspot_findings enable row level security;
drop policy if exists "blindspot_findings_all_own" on public.blindspot_findings;
create policy "blindspot_findings_all_own" on public.blindspot_findings for all using (auth.uid() = user_id);

-- ============ AI USAGE (for demo-mode capping) ============
create table if not exists public.ai_usage (
  user_id uuid references auth.users(id) on delete cascade not null,
  usage_date date not null default current_date,
  call_count integer default 0,
  primary key (user_id, usage_date)
);
alter table public.ai_usage enable row level security;

drop policy if exists "ai_usage_select_own" on public.ai_usage;
create policy "ai_usage_select_own" on public.ai_usage for select using (auth.uid() = user_id);
