# CLAUDE.md

Context for AI assistants (Claude Code or otherwise) working in this repo.

## What this is

DetectIQ — a multi-SIEM detection engineering platform. Analysts (detection
engineers, IR analysts, hunt analysts) build, tune, and validate detections
with AI assistance or manually, across Splunk, CrowdStrike, LogScale, Sentinel,
and others.

## Architecture

- `frontend/` — React + Vite SPA, plain CSS design system (no Tailwind/build
  plugin dependency — see `src/styles/tokens.css`), Supabase JS client talks
  directly to Supabase for all CRUD (RLS-protected per user).
- `backend/` — Express API. Its only job is to be the one place that holds AWS
  Bedrock credentials and proxy AI generation calls. It does not proxy
  detection CRUD — the frontend talks to Supabase directly for that.
- `supabase/schema.sql` — source of truth for all tables + RLS policies.

## Hard rules

- **AI provider is auto-selected**: if `ANTHROPIC_API_KEY` is set in the backend env, it's used directly (no AWS needed); otherwise the backend falls back to Bedrock. This is intentional now — see `backend/src/ai.js`. Don't reintroduce a hardcoded assumption that only Bedrock exists.
- When using the direct Anthropic API path, `ANTHROPIC_MAX_DAILY_CALLS` (default 50) is a hard in-memory ceiling on AI calls per day, since that path is pay-per-token with no natural spend limit. It resets on process restart — it's a safety net, not a substitute for a real spend limit set in the Anthropic Console.
- Detection CRUD goes through Supabase directly from the frontend (RLS
  enforces per-user isolation). Only AI generation goes through the backend.
- Demo-mode (`DEMO_MODE=true` on the backend) caps AI calls per user/day — see
  `backend/src/rateLimiter.js`. Never remove this cap on the public
  detect-iq.com deploy.
- Frontend components live one-per-file under `src/components` / `src/pages`.
  Don't reintroduce a monolithic App.jsx — that was the source of repeated
  white-screen/corruption issues in the previous version.
- Cloudflare must be configured as a trusted proxy in front of the backend for
  `express-rate-limit` to see real client IPs.

## Known non-obvious Supabase gotchas

- RLS on `teams` uses `owner_id`, not `user_id`.
- `detection_versions` requires an `auth.uid()::text` cast in its policy — the
  bare UUID comparison silently fails.
