# DetectIQ

<p align="center">
  <strong>AI-powered detection engineering platform for SOC teams</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#demo">Demo</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

DetectIQ is an **open-source, self-hosted** SIEM detection engineering platform that leverages AI to help security teams build, test, and deploy threat detection rules faster. Powered by AWS Bedrock (Claude Sonnet 4.6), it automates tedious detection engineering tasks while keeping SOC analysts in full control.

**Built for**: SOC Analysts, Detection Engineers, Threat Hunters, Security Architects

## 🚀 Deployment Model

**DetectIQ is self-hosted** - you run it on your own infrastructure:

✅ **What you get:**
- Full source code (MIT License - use, modify, distribute freely)
- Complete control over your data
- Run on your own servers (local, AWS EC2, Docker, Kubernetes, etc.)

### 📋 What You Need to Run DetectIQ

#### **Required (App won't work without these):**

1. **AWS Account with Bedrock access** ([sign up](https://aws.amazon.com/bedrock/))
   - Your own AWS credentials (access key + secret key)
   - Claude Sonnet 4.6 model enabled in Bedrock
   - **Cost**: Pay-as-you-go (~$5-30/month depending on usage)
   - **What it's used for**: All AI features (detection generation, translation, etc.)

2. **Redis** (open source, self-hosted)
   - **Cost**: FREE (run on your server)
   - Can use: Local Redis, AWS ElastiCache, Redis Cloud free tier
   - **What it's used for**: Response caching + BullMQ job queues

3. **Node.js 18+** and **npm**
   - **Cost**: FREE
   - **What it's used for**: Running the application

4. **A server to run it on**
   - **Cost**: $5-50/month (DigitalOcean, AWS, your laptop)
   - Minimum: 1 vCPU, 2GB RAM
   - Can run on: Local machine, cloud VM, Docker, Kubernetes

#### **Optional (App works without, but you lose features):**

5. **Supabase** (for user accounts & team collaboration)
   - **Cost**: FREE tier available ([sign up](https://supabase.com))
   - If you don't use Supabase:
     - ✅ DetectIQ works fine (uses browser localStorage)
     - ❌ Can't create user accounts
     - ❌ Can't share detections with team
     - ❌ No detection library sync across devices
   - **What it's used for**: PostgreSQL database, user auth, detection storage

6. **Resend** (for password reset emails)
   - **Cost**: FREE tier: 100 emails/day ([sign up](https://resend.com))
   - **What it's used for**: Sending password reset emails
   - If you don't use it: Users can't reset passwords via email

### 💡 **TL;DR - Minimum Setup:**

**For personal use (single user, no team features):**
- AWS Bedrock (required, ~$5-10/month)
- Redis (free, run locally)
- Any $5/month server or your laptop
- **Total cost**: ~$10-15/month

**For team use (5-20 users with collaboration):**
- AWS Bedrock (required, ~$20-40/month)
- Redis (free or $10/month managed)
- Supabase (free tier or $25/month for more storage)
- $10-30/month server
- **Total cost**: ~$30-80/month

**Compare to commercial tools**: Most SIEM detection platforms charge $1000-5000+ per user per year.

## Demo

🌐 **Live demo**: https://detect-iq.com

> Try all features with limited usage. No signup required for demo mode. For production use, deploy your own instance - see [Quick Start](#quick-start) below.

### Screenshots

> **Note**: Screenshots below show a demo account with sample data. Your installation will start empty - you'll build your own detection library from scratch.

**Dashboard - Overview & Coverage**
![Dashboard](docs/screenshots/dashboard.jpg)
*Dashboard overview showing detection library stats, MITRE ATT&CK coverage metrics, severity distribution, and quick-launch shortcuts. (Demo shows 82 rules - you'll start with 0 and build your library)*

**Detection Builder - AI-Powered Rule Generation**
![Detection Builder](docs/screenshots/detection-builder.jpg)
*Generate detection rules from plain-English threat scenarios across 10 SIEM platforms with the ADS (Attack Detection Strategy) framework. Select your SIEM, describe the threat, and get production-ready queries.*

**Detection Chain Builder - Multi-Stage Correlation**
![Detection Chain](docs/screenshots/detection-chain.jpg)
*Build multi-stage detection chains that track attackers across the kill chain. Chain detections for Discovery → Collection stages with automatic correlation logic and visual playbooks.*

**Autopilot - Auto-Generate from Threat Intel**
![Autopilot](docs/screenshots/autopilot.jpg)
*Auto-draft detections from 4 threat intelligence sources: CVEs (CISA KEV), ATT&CK TTPs (20 techniques), Threat Actors (8 APT groups), and Ransomware groups (6 major families). Queue-based workflow with approval process.*

**ATT&CK Coverage Heatmap**
![ATT&CK Map](docs/screenshots/attack-map.jpg)
*Visualize your detection coverage across MITRE ATT&CK tactics and techniques with maturity scoring. See gaps at a glance and prioritize detection development. (Demo shows 64% maturity across 9/14 tactics)*

**Dashboard - Honeycomb View**
![Dashboard Honeycomb](docs/screenshots/dashboard-honeycomb.jpg)
*Interactive honeycomb visualization showing coverage intensity by tactic. Hover over cells to see technique details. Color-coded: green (strong), yellow (partial), orange (minimal), gray (no coverage).*

**Detection Library - Manage & Deploy**
![Library](docs/screenshots/library.jpg)
*Your centralized detection library. Search, filter by tactic/severity/platform, export to Sigma, push directly to SIEM, or share with team. Each detection gets a quality score (0-100) based on 8 criteria. (Demo shows 82 rules - you start with 0)*

**Query Translator - Cross-Platform**
![Query Translator](docs/screenshots/query-translator.jpg)
*Translate detection queries between 10 SIEM platforms instantly. Example shows Splunk SPL → Falcon LogScale translation. Supports bidirectional translation between any platform pair.*

**Adversary SIEM - Red Team Simulator**
![Adversary SIEM](docs/screenshots/adversary-siem.jpg)
*Generate realistic attack logs to test your detections before deployment. Select attack technique, customize parameters, and get authentic log samples. Test detection coverage without running actual attacks.*

**Atomic Tests - Real Attack Procedures**
![Atomic Tests](docs/screenshots/atomic-tests.jpg)
*Browse 141+ Atomic Red Team tests across all MITRE tactics. View test commands with resolved arguments, then auto-generate matching detections. Example shows T1114.001 (Email Collection with PowerShell).*

**Defend Tools - Honeytokens & Sinkhole**
![Defend](docs/screenshots/defend-honeytokens.jpg)
*Generate honeytokens (fake credentials, canary files, AWS keys, DNS canaries) and DNS sinkhole configs for zero-false-positive detection. Load threat context from your detection library.*

**Get Started Guide**
![Get Started](docs/screenshots/get-started.jpg)
*Interactive onboarding walks you through building your first detection, reviewing detections in your library, and exploring key features. Complete 7 steps to go from zero to full MITRE coverage.*

**Documentation**
![Documentation](docs/screenshots/documentation.jpg)
*Built-in searchable documentation with 19 articles covering every feature. Includes quick links, examples, and best practices. Categories: Getting Started, Build, Analyze, Intel, Settings.*

## Features

### 🔨 Build Detections

#### Detection Builder (ADS Framework)
- **AI-powered detection generation** from threat scenarios
- Generates complete **Attack Detection Strategy (ADS)** output
- Supports all MITRE ATT&CK tactics and 100+ techniques
- Multi-SIEM support with platform-specific optimizations
- Includes: detection query, threat description, data requirements, false positive analysis, response playbook

#### Detection Chain Builder
- **Multi-stage correlation rules** - chain 2+ detections across the kill chain
- **Visual playbook generation** with attack narratives, timelines, and response steps
- **Smart tactic suggestions** based on MITRE ATT&CK sequencing
- **Coverage gap analysis** - identifies missing detection stages
- Export correlation searches for Splunk ES, Elastic, Sentinel

#### Query Translator
Translate detection queries across **10 SIEM platforms**:
- **Splunk** (SPL)
- **Microsoft Sentinel** (KQL)
- **Elastic** (EQL/KQL)
- **CrowdStrike** (Falcon LogScale)
- **Google Chronicle** (YARA-L)
- **IBM QRadar** (AQL)
- **Sumo Logic**
- **Tanium Signals**
- **Panther** (Python)
- **Humio/LogScale**

#### Atomic Red Team Integration
- Browse **50+ curated Atomic tests** across all MITRE tactics
- View test commands with resolved arguments
- Generate matching detections automatically
- Platform support: Windows, Linux, macOS, Cloud

#### Log Replay (Dry-Run Testing)
- Test detections against real log samples **before deployment**
- AI evaluates which log lines match your detection logic
- Identifies false positives and coverage gaps
- Supports all SIEM query languages

#### Defend Tools
- **Honeytokens** - canary credentials, fake API keys, decoy files
- **DNS Sinkhole** - catch malware C2 callbacks
- **Living Off the Land (LotL) detection** - detect abuse of built-in OS tools

### 📊 Analyze Coverage

#### Detection Library
- Centralized storage for all your detections
- Search, filter by tactic/severity/platform
- Quality scoring (0-100) based on 8 criteria
- Export to Sigma, push to SIEM, version control
- Share detections with team via Community tab

#### MITRE ATT&CK Coverage Map
- **Heatmap visualization** of coverage across 14 tactics
- **Honeycomb view** for gap analysis
- Track coverage by technique and sub-technique
- Identify blind spots in your detection strategy

#### Alert Triage
- **AI verdict engine** for rapid alert analysis
- Confidence scores + attack classification (true positive / false positive / benign)
- Recommended containment actions
- Context-aware analysis using historical patterns

#### Adversary SIEM
- **Simulate attacker behavior** and generate realistic logs
- Test if your SIEM detections would fire
- Supports: Mimikatz, Cobalt Strike, ransomware, lateral movement, persistence techniques
- Multi-platform log generation (Windows Event Logs, Sysmon, EDR, network)

#### Detection Health Monitor
- **Quality score dashboard** - tracks detection effectiveness
- **Blast radius estimation** - predict alert volume before deployment
- **False positive prediction** - ML-based FP rate estimates
- **ML enhancement suggestions** - UBA, risk-based scoring, anomaly detection
- **SOAR workflow builder** - automated response playbooks

### 🌐 Threat Intelligence

#### Autopilot - Auto-generate Detections
Automatically draft detection rules from **4 threat intelligence sources**:

1. **CVE Feed** - CISA Known Exploited Vulnerabilities (KEV) catalog
2. **ATT&CK TTPs** - 20 curated high-impact techniques
3. **Threat Actors** - 8 APT groups (Lazarus, APT29, APT28, APT1, FIN7, Sandworm, Kimsuky, MuddyWater)
4. **Ransomware** - 6 major groups (LockBit, BlackCat/ALPHV, Cl0p, Play, BlackBasta, Akira)

Features:
- Queue-based drafting with real-time progress tracking
- Filter drafts by source type (CVE, TTP, Actor, Ransomware)
- One-click save to library or edit in Detection Builder
- Runs asynchronously via BullMQ job queue

#### Threat Intel Dashboard
- Live **CISA KEV catalog** with severity ratings
- CVE details with CVSS scores and exploitation evidence
- APT group profiles with TTPs and infrastructure IOCs
- Campaign timelines and attribution

### ⚙️ Deployment & Collaboration

#### SIEM Push Integration
Push detections directly to your SIEM from DetectIQ:
- **Splunk Enterprise Security**
- **Elastic Security**
- **Microsoft Sentinel**
- **Chronicle**
- **QRadar**
- **CrowdStrike**
- **LogScale**
- **Tanium**
- **Panther**
- **Sumo Logic**

All pushes are logged in audit trail with timestamps, user ID, and status.

#### Export Formats
- **Sigma rules** - YAML format for universal SIEM compatibility
- **JSON** - bulk import/export for backup
- **Markdown** - documentation generation
- **GitHub** - push detections to version control repo

#### Team Collaboration
- Invite team members with email
- Share detections via Community tab
- Star/clone detections from teammates
- Role-based access control

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   React     │─────▶│   Express    │─────▶│ AWS Bedrock │
│  Frontend   │      │   Backend    │      │   (Claude)  │
│  (Vite)     │◀─────│  (Node.js)   │◀─────│  Sonnet 4.6 │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            ├─────▶ Redis (BullMQ queues)
                            └─────▶ Supabase (PostgreSQL)
```

### Tech Stack

**Frontend**
- React 18 with Hooks
- Vite (fast builds, HMR)
- No UI framework - custom components with inline styles
- Client-side routing (SPA)

**Backend**
- Node.js + Express
- BullMQ job queues (async AI processing)
- Redis (caching + job queue storage)
- Supabase (PostgreSQL for user data, detections, audit logs)
- jsonrepair (handles truncated AI JSON responses)

**AI**
- AWS Bedrock (Claude Sonnet 4.6)
- Streaming responses for real-time feedback
- Response caching with Redis
- max_tokens: 4000+ for complex outputs

**Security**
- Helmet.js (security headers)
- Rate limiting with Redis backend
- CORS with whitelist
- Compression (gzip)
- Input sanitization

**Deployment**
- PM2 (process management)
- Nginx (reverse proxy + static file serving)
- Ubuntu Linux on AWS EC2

## Quick Start

### Prerequisites

**Minimum (Required):**
- Node.js 18+ and npm
- Redis 6+ ([install instructions](#5-redis-setup))
- AWS account with Bedrock access ([enable Claude Sonnet 4.6](https://console.aws.amazon.com/bedrock/home#/modelaccess))

**Optional (For team features):**
- Supabase account (free tier works - [signup here](https://supabase.com/))
- Resend account for emails (free tier - [signup here](https://resend.com/))

### 1. Clone the repository

```bash
git clone https://github.com/vamshi-narahari/detect-iq.git
cd detect-iq
```

### 2. Backend Setup

```bash
cd backend
npm install

# Create .env file
cp .env.example .env
```

Edit `.env` with your credentials:
```bash
# ========================================
# REQUIRED - App won't work without these
# ========================================

# AWS Bedrock (for AI features)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6

# Redis (for caching + job queues)
REDIS_URL=redis://127.0.0.1:6379

# Server
PORT=3001

# ========================================
# OPTIONAL - Skip these for personal use
# ========================================

# Supabase (for user accounts, team collaboration)
# Leave commented out to use localStorage instead
# SUPABASE_URL=https://your-project.supabase.co
# SUPABASE_ANON_KEY=your_supabase_anon_key
# SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# Email (for password reset emails)
# Leave commented out if you don't need password reset
# RESEND_API_KEY=your_resend_api_key
```

Start the backend:
```bash
node server.js
```

Backend will run on `http://localhost:3001`

### 3. Frontend Setup

```bash
cd frontend
npm install

# Create .env file (optional - only needed for Supabase)
cp .env.example .env
```

Edit `.env` (optional - skip this if not using Supabase):
```bash
# Only needed if you set up Supabase in backend .env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
```

**Note:** Frontend will work fine without this - detections will be stored in browser localStorage.

Start the frontend:
```bash
npm run dev
```

Frontend will run on `http://localhost:5173`

### 4. AWS Bedrock Setup

1. Go to [AWS Console → Bedrock → Model access](https://console.aws.amazon.com/bedrock/home#/modelaccess)
2. Click **"Manage model access"**
3. Check **"Claude 3.5 Sonnet v2"** (model ID: `us.anthropic.claude-sonnet-4-6`)
4. Click **"Request model access"** (approval is instant for Sonnet)
5. Ensure your IAM user/role has the `bedrock:InvokeModel` permission:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:us-east-1::foundation-model/us.anthropic.claude-sonnet-4-6"
    }
  ]
}
```

### 5. Redis Setup

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl enable redis
sudo systemctl start redis
```

**macOS (Homebrew):**
```bash
brew install redis
brew services start redis
```

**Docker:**
```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

Verify Redis is running:
```bash
redis-cli ping
# Should return: PONG
```

### 6. Supabase Setup (Optional - Skip if Not Needed)

**You can skip this entire section if:**
- You're the only user
- You don't need team collaboration
- You're okay with detections stored in browser localStorage

**Set up Supabase only if you want:**
- Multiple user accounts with login/signup
- Detection library synced across devices
- Team detection sharing via Community tab
- Audit logs for SIEM push operations

---

**Setup steps:**

1. Create a free account at [supabase.com](https://supabase.com)
2. Create a new project
3. Go to **Settings → API** and copy:
   - Project URL (`SUPABASE_URL`)
   - anon/public key (`SUPABASE_ANON_KEY`)
   - service_role key (`SUPABASE_SERVICE_ROLE_KEY`)

4. Run SQL migrations (in Supabase SQL editor):

```sql
-- Detections table
CREATE TABLE detections (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL,
  name TEXT NOT NULL,
  query TEXT NOT NULL,
  tool TEXT NOT NULL,
  tactic TEXT,
  severity TEXT,
  description TEXT,
  tags TEXT[],
  score INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Community detections (shared)
CREATE TABLE community_detections (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL,
  name TEXT NOT NULL,
  query TEXT NOT NULL,
  tool TEXT NOT NULL,
  tactic TEXT,
  severity TEXT,
  threat TEXT,
  tags TEXT[],
  score INTEGER DEFAULT 0,
  star_count INTEGER DEFAULT 0,
  clone_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SIEM push audit log
CREATE TABLE siem_push_audit (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID,
  detection_id UUID,
  detection_name TEXT,
  platform TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT,
  ip_address TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE community_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_push_audit ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can CRUD their own detections"
  ON detections FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY "Anyone can read community detections"
  ON community_detections FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Users can insert their own community detections"
  ON community_detections FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);
```

## 🔧 Bring Your Own Infrastructure

**DetectIQ is flexible** - use your company's existing infrastructure instead of buying new services:

### Flexibility Matrix

| Component | Default | Alternatives | How to Swap |
|-----------|---------|--------------|-------------|
| **AI Model** | AWS Bedrock (Claude) | Azure OpenAI, Anthropic API, Local LLMs (Ollama) | Change API endpoint in backend |
| **Cloud Provider** | AWS | Azure, GCP, DigitalOcean, On-Prem | Deploy anywhere with Node.js |
| **Cache/Queue** | Redis | KeyDB, Valkey, Dragonfly, AWS ElastiCache, Azure Cache | Change REDIS_URL in .env |
| **Email** | Resend (optional) | Office 365/Outlook, SendGrid, AWS SES, company SMTP | Change email config in backend |
| **Database** | Browser localStorage (no DB!) | PostgreSQL, MySQL, MongoDB, SQL Server | Update backend code |
| **Web Server** | Nginx | Apache, IIS, Caddy, Traefik | Use any reverse proxy |
| **Process Manager** | PM2 | Systemd, Docker, Kubernetes, Supervisor | Use any process manager |

### Common Enterprise Scenarios

#### **Scenario 1: Microsoft Shop (Azure + Office 365)**
```bash
# Use Azure OpenAI instead of AWS Bedrock
AZURE_OPENAI_API_KEY=your_key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=claude-3-5-sonnet

# Use Azure Cache for Redis
REDIS_URL=redis://your-cache.redis.cache.windows.net:6380?password=your_password

# Use Office 365 for emails (via Microsoft Graph API)
EMAIL_PROVIDER=microsoft
MICROSOFT_TENANT_ID=your_tenant
MICROSOFT_CLIENT_ID=your_client_id
MICROSOFT_CLIENT_SECRET=your_secret
```

#### **Scenario 2: Google Cloud Shop (GCP + Gmail)**
```bash
# Use Anthropic API direct (GCP hosts it)
ANTHROPIC_API_KEY=your_api_key
ANTHROPIC_BASE_URL=https://api.anthropic.com

# Use Google Cloud Memorystore for Redis
REDIS_URL=redis://10.0.0.3:6379

# Use Gmail API for emails
EMAIL_PROVIDER=gmail
GMAIL_CLIENT_ID=your_client_id
GMAIL_CLIENT_SECRET=your_secret
```

#### **Scenario 3: On-Premises / Air-Gapped**
```bash
# Use local LLM (Ollama, LM Studio)
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3:70b

# Use on-prem Redis cluster
REDIS_URL=redis://redis-cluster.internal:6379

# Use company SMTP server
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.company.local
SMTP_PORT=587
SMTP_USER=detectiq@company.com
SMTP_PASSWORD=your_password
```

#### **Scenario 4: AWS Shop with Existing Services**
```bash
# Use AWS SES for emails (instead of Resend)
EMAIL_PROVIDER=aws-ses
AWS_SES_REGION=us-east-1
AWS_SES_FROM_EMAIL=detectiq@company.com

# Use AWS ElastiCache for Redis
REDIS_URL=redis://detectiq-cache.abc123.0001.use1.cache.amazonaws.com:6379

# Use AWS RDS PostgreSQL (instead of Supabase)
DATABASE_URL=postgresql://user:pass@detectiq-db.xyz.rds.amazonaws.com:5432/detectiq
```

---

### 🔌 How to Swap Infrastructure Components

#### **1. Swap AI Provider (AWS Bedrock → Azure/GCP/Local)**

**Current (AWS Bedrock):**
```javascript
// backend/server.js - line ~11
const bedrock = new BedrockRuntimeClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});
```

**Option A: Azure OpenAI**
```javascript
// Install: npm install @azure/openai
const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");
const client = new OpenAIClient(
  process.env.AZURE_OPENAI_ENDPOINT,
  new AzureKeyCredential(process.env.AZURE_OPENAI_API_KEY)
);
```

**Option B: Anthropic API Direct**
```javascript
// Install: npm install @anthropic-ai/sdk
const Anthropic = require('@anthropic-ai/sdk');
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});
```

**Option C: Local LLM (Ollama)**
```javascript
// Install: npm install ollama
const ollama = require('ollama');
// Calls go to http://localhost:11434
```

**Implementation:** Modify `backend/server.js` lines 11-50 (Bedrock initialization) and 261-370 (API calls)

---

#### **2. Swap Email Provider (Resend → Office 365/Gmail/SMTP)**

**Current (Resend):**
```javascript
// backend/server.js - line ~633
const resend = new Resend(process.env.RESEND_API_KEY);
await resend.emails.send({ from, to, subject, html });
```

**Option A: Office 365 / Outlook (Microsoft Graph API)**
```javascript
// Install: npm install @microsoft/microsoft-graph-client
const { Client } = require('@microsoft/microsoft-graph-client');
const client = Client.init({
  authProvider: (done) => {
    done(null, accessToken); // Get via OAuth2
  }
});
await client.api('/me/sendMail').post({
  message: { subject, body: { contentType: 'HTML', content: html }, toRecipients }
});
```

**Option B: Gmail API**
```javascript
// Install: npm install googleapis
const { google } = require('googleapis');
const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
await gmail.users.messages.send({
  userId: 'me',
  requestBody: { raw: Buffer.from(emailContent).toString('base64') }
});
```

**Option C: Company SMTP Server**
```javascript
// Install: npm install nodemailer
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
});
await transporter.sendMail({ from, to, subject, html });
```

**Implementation:** Modify `backend/server.js` lines 633-660 (email sending)

---

#### **3. Swap Redis (Redis → KeyDB/Valkey/ElastiCache)**

**Good news:** Redis alternatives are **drop-in compatible**! Just change the `REDIS_URL`:

```bash
# AWS ElastiCache
REDIS_URL=redis://your-cache.abc123.0001.use1.cache.amazonaws.com:6379

# Azure Cache for Redis
REDIS_URL=redis://your-cache.redis.cache.windows.net:6380?password=your_password

# Google Cloud Memorystore
REDIS_URL=redis://10.0.0.3:6379

# KeyDB (faster Redis alternative)
REDIS_URL=redis://localhost:6379

# Dragonfly (modern Redis alternative)
REDIS_URL=redis://localhost:6379

# Valkey (AWS fork of Redis)
REDIS_URL=redis://localhost:6379
```

**No code changes needed** - BullMQ and redis client work with all Redis-compatible services.

---

#### **4. Add Database (PostgreSQL/MySQL instead of localStorage)**

**Current:** Detections stored in browser localStorage (no database)

**To add PostgreSQL:**

1. **Install PostgreSQL driver:**
```bash
cd backend
npm install pg
```

2. **Add connection:**
```javascript
// backend/server.js - add after line 19
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});
```

3. **Create tables:**
```sql
CREATE TABLE detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id VARCHAR(255),
  name TEXT NOT NULL,
  query TEXT NOT NULL,
  tool VARCHAR(50) NOT NULL,
  tactic VARCHAR(100),
  severity VARCHAR(50),
  description TEXT,
  tags TEXT[],
  created_at TIMESTAMP DEFAULT NOW()
);
```

4. **Update API endpoints** (lines 1395-1434):
```javascript
// GET /api/detections
app.get("/api/detections", async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM detections WHERE user_id = $1 ORDER BY created_at DESC',
    [req.user.id]
  );
  res.json(rows);
});

// POST detection (save)
app.post("/api/detections", async (req, res) => {
  const { name, query, tool, tactic, severity, description, tags } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO detections (user_id, name, query, tool, tactic, severity, description, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
    [req.user.id, name, query, tool, tactic, severity, description, tags]
  );
  res.json(rows[0]);
});
```

**For MySQL:** Use `mysql2` package, same approach
**For MongoDB:** Use `mongodb` package, store as JSON documents
**For SQL Server:** Use `mssql` package, same SQL queries

---

#### **5. Deploy on Different Clouds**

**Azure:**
```bash
# Use Azure VM, Azure Redis Cache, Azure OpenAI
# Follow "Deploy on Your Own" guide, but:
az vm create --resource-group detectiq --name detectiq-vm --image Ubuntu2204
az redis create --resource-group detectiq --name detectiq-cache --sku Basic --vm-size C0
```

**GCP (Google Cloud):**
```bash
# Use Compute Engine, Memorystore, Anthropic API
gcloud compute instances create detectiq-vm --machine-type=e2-medium --image-family=ubuntu-2204-lts
gcloud redis instances create detectiq-cache --size=1 --region=us-central1
```

**On-Premises:**
```bash
# Install on any Ubuntu/CentOS server
# Use local Redis, local LLM (Ollama), no internet needed
# Follow "Deploy on Your Own" guide as-is
```

**All clouds work the same way** - DetectIQ is just Node.js + Redis + AI API, runs anywhere!

---

### 💡 **Why This Matters**

**No Vendor Lock-In:**
- ✅ Use your company's existing Microsoft 365 → don't buy Resend
- ✅ Deploy on Azure/GCP → don't need AWS
- ✅ Use your Redis cluster → don't need new cache
- ✅ Use company SMTP → don't need email service
- ✅ Add your own database → don't need Supabase

**Cost Savings:**
- Use enterprise agreements you already have
- Leverage existing infrastructure
- No redundant services

**Compliance:**
- Stay within approved vendor list
- Use company-managed services
- Data stays in your approved regions

---

## 🌐 Deployment Options

DetectIQ can be deployed in multiple ways depending on your needs:

### Quick Comparison

| Deployment Type | Best For | Complexity | Cost | Setup Time |
|-----------------|----------|------------|------|------------|
| **Local Dev** | Testing, personal use | Easy | Free (just AI) | 5 mins |
| **Company Internal** | SOC teams, secure deployment | Medium | Varies by infra | 30 mins |
| **Docker** | Clean isolated deployment | Medium | Varies by infra | 20 mins |
| **Cloud VM** | Public demo, production | Medium | $60-130/month | 45 mins |

---

## 🏢 Deploy on Your Own (Company/Enterprise)

**Perfect for:** SOC teams, internal deployment, no public access needed

**What you get:**
- ✅ Run on your own infrastructure (internal network only)
- ✅ No Supabase needed (detections in browser localStorage)
- ✅ No email/authentication setup needed
- ✅ Full control and data privacy
- ✅ ~$50-100/month (just AWS Bedrock AI costs)

### Prerequisites

- Company server or VM (1 vCPU, 2GB RAM minimum)
- AWS account with Bedrock access
- Node.js 18+ and npm
- Redis (will install in steps)

### Step 1: Prepare Server

**Ubuntu/Debian:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install Redis
sudo apt install -y redis-server
sudo systemctl enable redis
sudo systemctl start redis

# Verify installations
node --version  # Should be v18.x or higher
redis-cli ping  # Should return PONG
```

**CentOS/RHEL:**
```bash
sudo yum update -y
sudo yum install -y nodejs npm redis
sudo systemctl enable redis
sudo systemctl start redis
```

### Step 2: Clone and Configure

```bash
# Clone repository
cd /opt  # Or your preferred location
sudo git clone https://github.com/vamshi-narahari/detect-iq.git
sudo chown -R $USER:$USER detect-iq
cd detect-iq
```

### Step 3: Setup Backend

```bash
cd backend
npm install

# Create .env file (ONLY required variables)
cat > .env << 'EOF'
# ========================================
# REQUIRED - AWS Bedrock Configuration
# ========================================
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_company_aws_key_here
AWS_SECRET_ACCESS_KEY=your_company_aws_secret_here
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6

# Redis (local installation)
REDIS_URL=redis://127.0.0.1:6379

# Server port
PORT=3001

# CORS - restrict to your internal network
# Format: comma-separated origins
ALLOWED_ORIGINS=http://internal-detectiq.company.local,http://10.0.0.50

# ========================================
# OPTIONAL - Skip these for internal use
# ========================================
# Supabase - not needed, detections stored in browser
# Resend - not needed, no email required
EOF

# Edit with your actual AWS credentials
nano .env  # or vim .env
```

**Get AWS Credentials:**
1. Go to AWS Console → IAM → Users
2. Create new user: `detectiq-service`
3. Attach policy with Bedrock access (see Step 4)
4. Create access key → Copy credentials to .env

### Step 4: AWS IAM Permissions (Security Best Practice)

Create IAM policy for DetectIQ with minimal permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DetectIQBedrockAccess",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:us-east-1::foundation-model/us.anthropic.claude-sonnet-4-6"
    }
  ]
}
```

Enable Claude Sonnet 4.6:
1. Go to AWS Console → Bedrock → Model access
2. Click "Manage model access"
3. Enable "Claude 3.5 Sonnet v2"
4. Wait for approval (instant)

### Step 5: Start Backend

```bash
# Test backend first
node server.js

# If working, stop it (Ctrl+C) and run with PM2 for production
sudo npm install -g pm2
pm2 start server.js --name detectiq-backend
pm2 save
pm2 startup  # Run the command it outputs
```

Backend should now be running on `http://localhost:3001`

### Step 6: Setup Frontend

```bash
cd ../frontend
npm install

# Build production version
npm run build

# Frontend is now in: dist/
# Copy to web server or serve directly
```

### Step 7: Serve Frontend

**Option A: Using nginx (Recommended)**

```bash
# Install nginx
sudo apt install -y nginx

# Create nginx config
sudo nano /etc/nginx/sites-available/detectiq
```

Paste this config:
```nginx
server {
    listen 80;
    server_name internal-detectiq.yourcompany.local;  # Change to your internal domain

    # Optional: Basic authentication for security
    # auth_basic "DetectIQ - SOC Team";
    # auth_basic_user_file /etc/nginx/.htpasswd;

    # Frontend
    location / {
        root /opt/detect-iq/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Enable and start:
```bash
sudo ln -s /etc/nginx/sites-available/detectiq /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

**Option B: Using Node.js serve (Quick & Simple)**

```bash
sudo npm install -g serve
pm2 start "serve -s dist -l 80" --name detectiq-frontend
pm2 save
```

### Step 8: Configure Firewall (Security)

**Only allow access from company network:**

```bash
# Ubuntu/Debian with ufw
sudo ufw allow from 10.0.0.0/8 to any port 80
sudo ufw allow from 10.0.0.0/8 to any port 3001
sudo ufw enable

# Or restrict to specific subnet
sudo ufw allow from 10.50.100.0/24 to any port 80
```

### Step 9: (Optional) Add Basic Authentication

Protect with username/password:

```bash
# Install apache2-utils
sudo apt install apache2-utils

# Create users
sudo htpasswd -c /etc/nginx/.htpasswd soc_analyst1
sudo htpasswd /etc/nginx/.htpasswd soc_analyst2
sudo htpasswd /etc/nginx/.htpasswd threat_hunter1

# Uncomment auth lines in nginx config (Step 7)
sudo systemctl restart nginx
```

### Step 10: Access DetectIQ

1. **Add DNS entry** (ask IT team):
   - Point `internal-detectiq.company.local` to your server IP
   - Or use IP directly: `http://10.0.x.x`

2. **Access from browser**:
   - Open: `http://internal-detectiq.company.local`
   - Or: `http://your-server-ip`

3. **Start using**:
   - No signup needed (no Supabase)
   - Each user's detections stored in their browser
   - Build detections, chains, use autopilot immediately

### Multi-User Setup (Without Supabase)

Since detections are stored in browser localStorage, here are options for team sharing:

**Option 1: Export/Import via Shared Drive**
```bash
# Each analyst can export detections:
Library → Export JSON → Save to: \\company-nas\soc\detectiq-detections\

# Others can import:
Library → Import JSON → Select file from shared drive
```

**Option 2: Git Repository**
```bash
# Create shared repo
git clone git@internal-git.company.com:soc/detections.git

# Analysts commit their detections:
Library → Export JSON → git add → git commit → git push

# Others pull latest:
git pull → Library → Import JSON
```

**Option 3: Add PostgreSQL (Advanced)**

If you need real multi-user with shared library, you can add PostgreSQL:

```bash
# Install PostgreSQL
sudo apt install postgresql

# Create database
sudo -u postgres psql
CREATE DATABASE detectiq;
CREATE USER detectiq WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE detectiq TO detectiq;

# Update backend .env:
DATABASE_URL=postgresql://detectiq:secure_password@localhost:5432/detectiq

# Run migrations (you'll need to implement this)
```

---

## 🐳 Docker Deployment

**Perfect for:** Clean isolated deployment, easy updates, portable

### Quick Start with Docker

**Prerequisites:**
- Docker and Docker Compose installed

**Step 1: Create project structure**

```bash
mkdir detectiq-docker && cd detectiq-docker
git clone https://github.com/vamshi-narahari/detect-iq.git
cd detect-iq
```

**Step 2: Create docker-compose.yml**

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis-data:/data

  backend:
    build: ./backend
    ports:
      - "3001:3001"
    environment:
      AWS_REGION: ${AWS_REGION:-us-east-1}
      AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID}
      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}
      BEDROCK_MODEL_ID: us.anthropic.claude-sonnet-4-6
      REDIS_URL: redis://redis:6379
      PORT: 3001
    depends_on:
      - redis
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: unless-stopped

volumes:
  redis-data:
```

**Step 3: Create .env file**

```bash
cat > .env << 'EOF'
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
EOF
```

**Step 4: Create Dockerfiles**

Backend Dockerfile (`backend/Dockerfile`):
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3001
CMD ["node", "server.js"]
```

Frontend Dockerfile (`frontend/Dockerfile`):
```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Frontend nginx config (`frontend/nginx.conf`):
```nginx
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://backend:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

**Step 5: Deploy**

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Access at: http://localhost
```

**Step 6: Updates**

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build
docker-compose up -d
```

---

## ☁️ Cloud VM Deployment (Public Access)

**Perfect for:** Public demo, internet-facing deployment with Supabase

This setup includes full user authentication, team collaboration, and public access. Follow the "Deploy on Your Own" guide above, then add:

### Additional Steps for Public Deployment:

**1. Set up Supabase** (see [Supabase Setup](#6-supabase-setup-optional---skip-if-not-needed))

**2. Configure domain with Cloudflare** (recommended for DDoS protection):
- Point your domain to server IP
- Enable Cloudflare proxy (orange cloud)
- Set SSL/TLS mode to "Full"
- Enable rate limiting rules

**3. Set up SSL with Let's Encrypt:**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

**4. Enable Supabase environment variables in backend `.env`:**
```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
```

**5. Configure frontend `.env`:**
```bash
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key
```

Now rebuild frontend and restart:
```bash
cd frontend && npm run build
sudo cp -r dist/* /var/www/detectiq/
pm2 restart detectiq-backend
```

---

## 📊 Deployment Comparison

| Feature | Company Internal | Docker | Cloud VM (Public) |
|---------|------------------|--------|-------------------|
| **Access** | Internal network only | Flexible | Internet-facing |
| **Supabase** | Not needed | Optional | Recommended |
| **Authentication** | Optional (nginx basic auth) | Optional | Yes (Supabase) |
| **SSL/Domain** | Optional | Optional | Required |
| **Cost** | $50-100/month | $50-100/month | $60-130/month |
| **Security** | Highest (firewalled) | High | Medium (use Cloudflare) |
| **Setup Time** | 30 mins | 20 mins | 45 mins |
| **Best For** | SOC teams | Clean isolated deploy | Public demos |

---

## 🔧 Maintenance & Updates

### Updating DetectIQ

```bash
# Pull latest code
cd /opt/detect-iq  # or your install path
git pull origin main

# Update backend
cd backend
npm install
pm2 restart detectiq-backend

# Update frontend
cd ../frontend
npm install
npm run build
sudo cp -r dist/* /var/www/detectiq/  # or your web root
```

### Monitoring

**Check service status:**
```bash
pm2 status
pm2 logs detectiq-backend
redis-cli ping
```

**Check disk space:**
```bash
df -h
du -sh /opt/detect-iq
```

**AWS Bedrock costs:**
- Check AWS Console → Billing Dashboard
- Set up budget alerts at $100/month

### Backup

**What to backup:**
```bash
# Backend .env (has AWS credentials)
cp /opt/detect-iq/backend/.env ~/backups/

# If using Supabase, database is backed up automatically
# If not using Supabase, detections are in browser localStorage (no server backup needed)
```

---

## 🆘 Troubleshooting

### Backend won't start

```bash
# Check logs
pm2 logs detectiq-backend

# Common issues:
# - AWS credentials invalid → Check .env
# - Redis not running → sudo systemctl start redis
# - Port 3001 in use → pm2 stop all, then pm2 start server.js
```

### Frontend shows blank page

```bash
# Check nginx logs
sudo tail -f /var/nginx/error.log

# Common issues:
# - Build failed → cd frontend && npm run build
# - Wrong path in nginx → Check root path in nginx config
# - API calls failing → Check CORS in backend .env
```

### AWS Bedrock errors

```bash
# Check IAM permissions
# User needs: bedrock:InvokeModel permission

# Check model access
# Go to AWS Console → Bedrock → Model access
# Ensure Claude Sonnet 4.6 is enabled

# Check region
# Model must be available in your AWS_REGION (use us-east-1)
```

### High AWS costs

```bash
# Check usage in AWS Console → Bedrock → Usage

# Reduce costs:
# 1. Enable response caching (already enabled in DetectIQ)
# 2. Reduce max_tokens in backend/server.js
# 3. Rate limit users in nginx
# 4. Use Haiku model for simple tasks (edit BEDROCK_MODEL_ID)
```

## 💰 Cost Estimate (Your Expense)

Since DetectIQ is self-hosted, you pay for the infrastructure and AI usage directly:

### AWS Bedrock (Claude Sonnet 4.6) - Required
- **Input tokens**: $3.00 per million tokens
- **Output tokens**: $15.00 per million tokens

**Typical usage** (100 detections/month):
- ~5 million input tokens = $15
- ~1 million output tokens = $15
- **Total AI cost**: ~$30/month

💡 **Lower usage?** If you generate 10-20 detections/month, expect ~$5-10/month.

### Infrastructure Options

**Option 1: Cheap ($10-15/month)**
- DigitalOcean Droplet ($6/month) or AWS Lightsail ($5-10/month)
- Good for: personal use, small teams (1-5 users)
- Specs: 1 vCPU, 2GB RAM

**Option 2: Production ($30-50/month)**
- AWS EC2 t3.medium ($30/month) or t3.small ($15/month)
- Good for: teams of 5-20 users, high availability
- Specs: 2 vCPU, 4GB RAM

**Option 3: Enterprise (Custom)**
- Kubernetes cluster, load balancing, Redis cluster
- Good for: 50+ users, mission-critical
- Contact your infrastructure team for sizing

### Total Cost Examples

| Use Case | AI Cost | Infrastructure | Total |
|----------|---------|----------------|-------|
| **Personal** (10 detections/month) | $5 | $6 (DigitalOcean) | **$11/month** |
| **Small team** (50 detections/month) | $15 | $10 (Lightsail) | **$25/month** |
| **SOC team** (100 detections/month) | $30 | $30 (EC2 t3.medium) | **$60/month** |
| **Enterprise** (500 detections/month) | $150 | Custom | **$200+/month** |

🎯 **Compare to commercial alternatives:** Most SIEM detection tools charge $1000-5000+/month per user.

## ❓ FAQ

### Do I need to pay for DetectIQ?
**No.** DetectIQ is 100% free and open source (MIT License). However, you pay for:
- AWS Bedrock AI usage (~$30/month for typical use)
- Your own server/hosting (~$5-30/month depending on size)

### Can I use it without AWS?
**Yes!** DetectIQ works with multiple AI providers. Just modify the backend code:
- ✅ **Azure OpenAI** - Use if you're on Microsoft Azure
- ✅ **Anthropic API Direct** - Use if you have Anthropic account
- ✅ **Google Cloud AI** - Use if you're on GCP
- ✅ **Local LLM (Ollama)** - Free, run on your hardware

See [How to Swap Infrastructure](#-how-to-swap-infrastructure-components) for code examples.

### Do I need Supabase?
**No, it's optional.** DetectIQ works without Supabase:
- **Without Supabase**: Detections stored in browser localStorage (single user only)
- **With Supabase**: Multi-user support, detection library sync, team sharing

**Get Supabase free:** https://supabase.com (50,000 rows, 500MB storage on free tier)

### Do I need Resend for emails?
**No, it's optional.** Only needed if you want password reset emails. You can also use:
- ✅ **Office 365 / Outlook** - If you use Microsoft email
- ✅ **Gmail API** - If you use Google Workspace
- ✅ **Company SMTP** - Your internal mail server
- ✅ **AWS SES** - If you're on AWS
- ❌ **Skip email entirely** - Most companies do this for internal tools

See [How to Swap Infrastructure](#-how-to-swap-infrastructure-components) for code examples.

### Is my data sent to Anthropic or other third parties?
**Only detection text goes to AWS Bedrock** for AI processing. Everything else stays on your server:
- Detection rules stored in your database
- User credentials in your Supabase
- No telemetry or analytics sent to us

### Can I modify the code?
**Yes!** MIT License means you can:
- ✅ Modify for your needs
- ✅ Use commercially (even sell it)
- ✅ Remove features you don't need
- ✅ Add features for your organization
- ⚠️ Just keep the MIT License and credit

### Can I use this at my company?
**Absolutely!** DetectIQ is designed for enterprise use. The MIT License allows commercial use.

**Best practices:**
- ✅ Use company's existing cloud (Azure/AWS/GCP/On-prem)
- ✅ Use company's existing email (Office 365/Gmail/SMTP)
- ✅ Deploy on internal network (no internet exposure)
- ✅ Use company's Redis/cache service
- ✅ Integrate with company SSO (optional)

See [Bring Your Own Infrastructure](#-bring-your-own-infrastructure) for using your existing services.
See [Deploy on Your Own](#-deploy-on-your-own-companyenterprise) for step-by-step enterprise deployment.

### How do I update DetectIQ when new versions are released?
```bash
cd ~/detect-iq-repo
git pull origin main
cd backend && npm install
cd ../frontend && npm install && npm run build
# Re-deploy (copy files, restart services)
```

### What if I don't want to self-host?
We're considering a hosted SaaS option in the future. For now, DetectIQ is self-hosted only. If you need help deploying, open a [GitHub Discussion](https://github.com/vamshi-narahari/detect-iq/discussions).

### Can I contribute back?
**Please do!** See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome:
- Bug fixes
- New SIEM platform support
- UI improvements
- Documentation updates
- Feature implementations from the roadmap

## Roadmap

- [ ] **Detection versioning** - git-like version control for detection rules
- [ ] **Multi-user workspaces** - team collaboration with role-based access
- [ ] **Custom AI models** - support for local LLMs (Ollama, LM Studio)
- [ ] **Sigma rule import** - bulk import from Sigma rule repository
- [ ] **Threat hunting assistant** - AI-powered hypothesis generation
- [ ] **SOAR integrations** - Splunk SOAR, Palo Alto Cortex XSOAR, Tines
- [ ] **Dark mode UI** - eye-friendly theme for late-night detection engineering
- [ ] **API documentation** - OpenAPI/Swagger spec
- [ ] **CLI tool** - command-line interface for CI/CD pipelines
- [ ] **Detection testing framework** - automated unit tests for detection logic
- [ ] **Jupyter notebook integration** - exploratory detection analysis

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to report bugs
- Feature request process
- Development setup
- Coding standards
- Pull request guidelines

**Quick links:**
- [Issues](https://github.com/vamshi-narahari/detect-iq/issues) - report bugs or request features
- [Discussions](https://github.com/vamshi-narahari/detect-iq/discussions) - ask questions, share ideas

## Community

- **GitHub Issues**: [Report bugs or request features](https://github.com/vamshi-narahari/detect-iq/issues)
- **GitHub Discussions**: [Ask questions, share tips](https://github.com/vamshi-narahari/detect-iq/discussions)
- **Reddit**: [r/blueteamsec](https://reddit.com/r/blueteamsec) - share your experience

## License

[MIT License](LICENSE) - free to use, modify, and distribute, including commercial use.

## Acknowledgments

- **AI**: Built with [Claude](https://www.anthropic.com/claude) by Anthropic
- **MITRE ATT&CK®**: Framework and data from [MITRE Corporation](https://attack.mitre.org/)
- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **Atomic Red Team**: Test automation by [Red Canary](https://github.com/redcanaryco/atomic-red-team)
- **Sigma**: Generic detection rule format by [SigmaHQ](https://github.com/SigmaHQ/sigma)

## Star History

If DetectIQ helps your SOC team, please give it a ⭐ on GitHub!

---

<p align="center">
  <strong>Built with ❤️ for the security community</strong><br>
  <sub>Made by <a href="https://github.com/vamshi-narahari">@vamshi-narahari</a></sub>
</p>
