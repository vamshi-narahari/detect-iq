# DetectIQ

AI-assisted detection engineering platform for SOC teams — build, tune, and
validate detections across multiple SIEMs from one workspace.

## Structure

```
detect-iq/
  frontend/     React + Vite SPA (design system, auth, detection library, etc.)
  backend/      Express API — proxies AI calls to Bedrock, never exposes AWS creds to the client
  supabase/     schema.sql — run in the Supabase SQL editor to (re)create all tables + RLS
```

## What's fully wired

- Supabase auth (sign up / sign in / sign out), session-aware routing, **"Try the demo" no-signup login** (env-configured shared account)
- Detection Library: full CRUD against Supabase, per-user RLS
- AI-assisted detection builder → backend `/api/claude` → Bedrock or direct Anthropic API → Claude
- **Query Translator**: converts a detection query between SIEM syntaxes via AI
- **MITRE Coverage**: tactic heatmap across the 14 canonical ATT&CK Enterprise tactics
- **Assets**: inventory management, separate from Macros, for enrichment lookups to reference
- Suppression rules: CRUD, global or per-detection, stored per-detection
- Demo mode: env-flag-driven AI call cap (see `backend/.env.example`)
- **Anthropic API spend guard**: hard daily call ceiling when using the direct API path (see `ANTHROPIC_MAX_DAILY_CALLS`)
- **Inbound webhook**: `POST /api/webhook/intake/:provider` — a real endpoint that creates Intake tickets, ready to be called by a Jira Automation rule, Power Automate flow, or Webex webhook once you configure the secret and point that vendor's automation at it
- Full new design system + shell (nav rail, top bar, dashboard) from the redesign

## What's scaffolded but needs your credentials/integration work to finish

- **Validation & Simulation**: UI + Supabase-backed run history is real; the
  actual trigger to SafeBreach / Atomic Red Team / a live SIEM query is a
  `// TODO` in `backend/src/routes/validate.js` — wire in whichever tool you
  connect first.
- **Integrations page**: connect/disconnect UI and status persist to Supabase;
  the actual OAuth/API handshake per SIEM/ticketing/chat provider is stubbed
  per-provider. The **webhook receiver** is real and working, but it still
  requires you to configure the outbound side in each vendor's console
  (Jira Automation, Power Automate for Outlook/Teams, a Webex webhook
  integration) — that's account-specific setup no code can do for you.
- **MITRE STIX auto-update**: not included this pass — coverage is computed
  from your own detections' tagged tactics/techniques, not a live STIX feed.

## Local setup

### Option A — Docker (recommended for trying it out or contributing)

```bash
cp .env.docker.example .env          # fill in Supabase URL/anon key
cp backend/.env.example backend/.env # fill in AWS Bedrock creds + Supabase service role
docker compose build
docker compose up -d
```

Visit `http://localhost:8080`. The frontend container serves the built app via
nginx and proxies `/api/*` to the backend container over the Docker network —
no manual Nginx setup needed for local use.

**What Docker does and doesn't cover:** it gives you a reproducible way to run
the whole stack. It does **not** wire up real SIEM/simulation/ticketing
connectors — those "Connect" toggles in Settings are status flags today, not
live API integrations. Testing against a real LogScale/Splunk/etc. tenant
still requires that connector's actual API code to be built against your
real credentials, container or not.

### Option B — Run natively

```bash
# frontend
cd frontend
cp .env.example .env        # fill in Supabase URL/anon key + backend API URL
npm install
npm run dev

# backend
cd backend
cp .env.example .env        # fill in AWS Bedrock creds/region + Supabase service role + ALLOWED_ORIGINS
npm install
npm run start
```

## Deploying to your EC2 (same workflow as before)

```bash
git pull
cp backend/server.js ~/detectiq-server/server.js   # or symlink the whole backend/ dir
pm2 restart all
cd frontend && npm run build
cp -r dist/* ~/detectiq-frontend/
```

## Database

Run `supabase/schema.sql` in the Supabase SQL editor. It's idempotent
(`create table if not exists`) so it's safe to re-run.

**AI provider:** set either the AWS Bedrock env vars OR `ANTHROPIC_API_KEY` in
`backend/.env` — whichever is set takes effect (Anthropic API key takes
priority if both are present). Direct Anthropic API usage is pay-per-token,
so `ANTHROPIC_MAX_DAILY_CALLS` in `backend/.env.example` caps daily calls as
a safety net; also set a real spend limit in your Anthropic Console.
