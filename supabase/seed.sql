-- DetectIQ demo seed data.
-- Run this AFTER schema.sql and AFTER you've signed up at least one account.
-- Safe to re-run: it clears prior seed rows for this user first.

do $$
declare uid uuid;
begin
  select id into uid from auth.users order by created_at limit 1;
  if uid is null then
    raise exception 'No user found — sign up an account first, then re-run this script.';
  end if;

  delete from public.suppression_rules where user_id = uid;
  delete from public.validation_runs where user_id = uid;
  delete from public.intake_requests where user_id = uid;
  delete from public.packs where user_id = uid;
  delete from public.detections where user_id = uid;
end $$;

-- ============ DETECTIONS ============
insert into public.detections (user_id, name, query, tool, tactic, technique_id, severity, description, status, source, tags, score)
select (select id from auth.users order by created_at limit 1), * from (values
  ('Password spraying against O365 from a single external IP', 'index=o365 sourcetype="o365:management:activity" Operation=UserLoginFailed | stats dc(user) as users, count by src_ip | where users > 10 AND count > 20', 'splunk', 'Credential Access', 'T1110.003', 'high', 'Detects a single external IP attempting many distinct usernames against O365 in a short window.', 'active', 'ai', array['tuned'], 91),
  ('Kerberoasting via abnormal TGS request volume', 'index=windows sourcetype="WinEventLog:Security" EventCode=4769 | stats count by user, service | where count > 15', 'splunk', 'Credential Access', 'T1558.003', 'high', 'Flags accounts requesting an unusually high number of service tickets, consistent with offline cracking prep.', 'active', 'ai', array[]::text[], 87),
  ('LSASS memory access by non-standard process', 'process_name!=lsass.exe AND target_process=lsass.exe AND access_mask=0x1010', 'crowdstrike', 'Credential Access', 'T1003.001', 'critical', 'Catches credential dumping attempts via direct LSASS memory reads.', 'active', 'manual', array['tuning'], 95),
  ('Encoded PowerShell launched from Word', 'index=windows sourcetype="WinEventLog:Security" parent_process=WINWORD.EXE process=powershell.exe cmd=*-enc*', 'splunk', 'Execution', 'T1059.001', 'high', 'Detects the classic macro-to-PowerShell dropper chain.', 'active', 'ai', array[]::text[], 88),
  ('Scheduled task persistence via unusual binary path', 'index=windows EventCode=4698 | where NOT match(TaskContent, "(?i)C:\\\\Windows\\\\System32")', 'splunk', 'Persistence', 'T1053.005', 'medium', 'Flags scheduled tasks pointing at binaries outside expected system paths.', 'active', 'manual', array[]::text[], 74),
  ('Run key persistence added by non-installer process', 'registry_path=*\\Run\\* AND process_name NOT IN ("msiexec.exe","setup.exe","TrustedInstaller.exe")', 'crowdstrike', 'Persistence', 'T1547.001', 'medium', 'Registry Run key modifications outside typical installer activity.', 'draft', 'ai', array[]::text[], 61),
  ('DNS tunneling via high-entropy subdomains', 'index=dns sourcetype="infoblox:dns" | eval entropy=shannon_entropy(query) | where entropy > 3.8 AND len(query) > 50', 'splunk', 'Exfiltration', 'T1071.004', 'medium', 'Flags DNS queries with entropy/length consistent with tunneled data.', 'draft', 'ai', array[]::text[], 58),
  ('Cloud storage sync to unapproved personal account', 'index=proxy sourcetype="zscalernss-web" url=*dropbox.com* OR url=*drive.google.com* | stats sum(bytes_out) as total by user | where total > 500000000', 'sentinel', 'Exfiltration', 'T1567.002', 'medium', 'Large outbound transfers to consumer cloud storage domains.', 'draft', 'manual', array[]::text[], 55),
  ('RDP lateral movement across multiple hosts by one account', 'index=windows EventCode=4624 LogonType=10 | stats dc(dest) as hosts by user | where hosts > 5', 'logscale', 'Lateral Movement', 'T1021.001', 'high', 'One account RDPing to an unusually wide set of hosts in a short window.', 'active', 'ai', array[]::text[], 82),
  ('Admin share access from workstation to workstation', 'index=windows share_name IN ("C$","ADMIN$") AND src_category=workstation AND dest_category=workstation', 'logscale', 'Lateral Movement', 'T1021.002', 'medium', 'Workstation-to-workstation admin share access, atypical of normal IT flow.', 'draft', 'manual', array[]::text[], 63),
  ('MFA fatigue via repeated push prompts', 'index=okta sourcetype="OktaIM2:log" eventType=user.mfa.okta_verify.deny_push | stats count by user | where count > 8', 'sentinel', 'Credential Access', 'T1621', 'high', 'Detects repeated MFA push denials consistent with prompt-bombing.', 'active', 'ai', array['tuned'], 84),
  ('AssumeRole from unfamiliar principal to sensitive role', 'index=aws sourcetype=aws:cloudtrail eventName=AssumeRole roleName=*Admin*', 'sentinel', 'Privilege Escalation', 'T1548.005', 'critical', 'AssumeRole calls into admin-tier roles from principals with no prior history.', 'draft', 'ai', array[]::text[], 90),
  ('Ransomware note file creation across shares', 'index=windows file_name IN ("*README*","*DECRYPT*") AND file_operation=create', 'crowdstrike', 'Impact', 'T1486', 'critical', 'File-creation pattern consistent with ransomware note drops across shares.', 'active', 'manual', array[]::text[], 93),
  ('New OAuth app granted broad mailbox permissions', 'index=o365 Operation=Add-OAuthApp | where match(Scope, "(?i)mail.readwrite")', 'sentinel', 'Persistence', 'T1098.003', 'high', 'Flags newly consented OAuth apps requesting broad mailbox scopes.', 'draft', 'ai', array[]::text[], 71)
) as t(name, query, tool, tactic, technique_id, severity, description, status, source, tags, score);

-- ============ PACKS ============
insert into public.packs (user_id, name, description, techniques)
select (select id from auth.users order by created_at limit 1), * from (values
  ('Credential Access', 'Password attacks, ticket abuse, and credential dumping.', array['T1110.003','T1558.003','T1003.001','T1621','T1110.001']),
  ('Persistence', 'Run keys and scheduled tasks.', array['T1053.005','T1547.001','T1098.003']),
  ('Exfil and C2', 'Alternate protocol, DNS, and cloud storage.', array['T1071.004','T1567.002','T1071.001']),
  ('Lateral Movement', 'RDP and admin shares.', array['T1021.001','T1021.002']),
  ('Impact', 'Encryption and inhibit recovery.', array['T1486','T1490'])
) as t(name, description, techniques);

-- ============ SUPPRESSION RULES (Allowlists) ============
insert into public.suppression_rules (user_id, detection_id, scope, field, op, value, reason, destination)
values
  ((select id from auth.users order by created_at limit 1), null, 'global', 'user', 'contains', 'svc_', 'Known service account prefix', 'all'),
  ((select id from auth.users order by created_at limit 1), null, 'global', 'src_ip', 'cidr', '10.0.0.0/8', 'Internal scanner range', 'all'),
  ((select id from auth.users order by created_at limit 1), (select id from public.detections where name = 'Password spraying against O365 from a single external IP'), 'detection', 'src_ip', 'equals', '203.0.113.4', 'Known pentest vendor IP', 'splunk'),
  ((select id from auth.users order by created_at limit 1), (select id from public.detections where name = 'RDP lateral movement across multiple hosts by one account'), 'detection', 'user', 'equals', 'svc_backup', 'Backup service account performs legitimate multi-host RDP', 'logscale');

-- ============ VALIDATION RUNS ============
insert into public.validation_runs (user_id, detection_id, method, status, fired, noise_events)
values
  ((select id from auth.users order by created_at limit 1), (select id from public.detections where name = 'Password spraying against O365 from a single external IP'), 'atomic_red_team', 'passed', true, 2),
  ((select id from auth.users order by created_at limit 1), (select id from public.detections where name = 'LSASS memory access by non-standard process'), 'synthetic', 'passed', true, 0),
  ((select id from auth.users order by created_at limit 1), (select id from public.detections where name = 'Run key persistence added by non-installer process'), 'synthetic', 'failed', false, 14),
  ((select id from auth.users order by created_at limit 1), (select id from public.detections where name = 'Scheduled task persistence via unusual binary path'), 'synthetic', 'queued', null, 0);

-- ============ INTAKE REQUESTS ============
insert into public.intake_requests (user_id, title, notes, priority, technique_id, source, status, detection_id)
values
  ((select id from auth.users order by created_at limit 1), 'Detect impossible travel on privileged accounts', 'Came up in this week''s IR retro.', 'high', 'T1078.004', 'manual', 'open', null),
  ((select id from auth.users order by created_at limit 1), 'Cover golden ticket abuse', 'Gap flagged by Credential Access pack.', 'critical', 'T1558.001', 'gap', 'open', null),
  ((select id from auth.users order by created_at limit 1), 'AssumeRole into admin roles', 'Hunt team wants an alert, not just a saved search.', 'high', 'T1548.005', 'builder', 'building', (select id from public.detections where name = 'AssumeRole from unfamiliar principal to sensitive role')),
  ((select id from auth.users order by created_at limit 1), 'Password spraying detection review', 'Ready for review before promoting to prod.', 'medium', 'T1110.003', 'manual', 'review', (select id from public.detections where name = 'Password spraying against O365 from a single external IP')),
  ((select id from auth.users order by created_at limit 1), 'Ransomware note detection', 'Deployed and validated.', 'critical', 'T1486', 'manual', 'done', (select id from public.detections where name = 'Ransomware note file creation across shares'));
