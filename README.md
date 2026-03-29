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
- Complete control over your data (nothing sent to external services except AWS Bedrock for AI)
- Run on your own servers (local, AWS EC2, Docker, Kubernetes, etc.)

⚠️ **What you need:**
- **AWS Account** with Bedrock access ([sign up here](https://aws.amazon.com/bedrock/))
- **Your own AWS credentials** (access key + secret key) - see [setup guide](#4-aws-bedrock-setup)
- **AI costs are yours** - AWS Bedrock pay-as-you-go (~$30-60/month for typical use)
- **Infrastructure costs** - server to run it on (can be as low as $5/month)

💡 **No vendor lock-in:** Your data stays on your infrastructure. You control everything.

## Demo

🌐 **Live demo**: http://3.134.146.190 (hosted by us for testing)

> Try all features instantly - no signup required for demo mode. This is our hosted instance for demo purposes only.

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

- Node.js 18+ and npm
- Redis 6+
- AWS account with Bedrock access ([enable Claude Sonnet 4.6](https://console.aws.amazon.com/bedrock/home#/modelaccess))
- Supabase account (free tier works - [signup here](https://supabase.com/))

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
# AWS Bedrock (required)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6

# Redis (required)
REDIS_URL=redis://127.0.0.1:6379

# Supabase (optional - needed for user accounts)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# Email (optional - for password reset)
RESEND_API_KEY=your_resend_api_key

# Server
PORT=3001
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

# Create .env file
cp .env.example .env
```

Edit `.env`:
```bash
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
```

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

### 6. Supabase Setup (Optional)

DetectIQ works without Supabase (uses local storage), but for user accounts and team collaboration:

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

## 🌐 Deployment

You can deploy DetectIQ to any server or cloud platform. Choose based on your needs:

### Option 1: Local Development (Easiest - Start Here!)

Perfect for testing and personal use:

```bash
# 1. Clone repo
git clone https://github.com/vamshi-narahari/detect-iq.git
cd detect-iq

# 2. Start backend
cd backend
cp .env.example .env
# Edit .env with your AWS credentials
npm install
node server.js &

# 3. Start frontend (in new terminal)
cd frontend
npm install
npm run dev
```

Access at: `http://localhost:5173`

### Option 2: Docker (Recommended for Production)

**Coming soon!** We're working on Docker Compose setup. For now, use manual deployment below.

### Option 3: Cloud VM (AWS EC2, DigitalOcean, Lightsail)

Deploy to any Ubuntu/Debian server:

The live demo runs on:
- **Instance**: AWS EC2 t3.medium (2 vCPU, 4GB RAM)
- **OS**: Ubuntu 22.04 LTS
- **Cost**: ~$30/month

**Setup steps:**

1. **Install dependencies:**
```bash
# Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Redis
sudo apt install redis-server
sudo systemctl enable redis

# PM2
sudo npm install -g pm2

# Nginx
sudo apt install nginx
```

2. **Deploy backend:**
```bash
cd ~/detectiq-server
npm install --production
pm2 start server.js --name detectiq-api
pm2 save
pm2 startup  # Run the command it outputs
```

3. **Deploy frontend:**
```bash
cd ~/detect-iq-repo/frontend
npm run build
sudo cp -r dist/* /var/www/detectiq/
```

4. **Configure Nginx** (`/etc/nginx/sites-available/detectiq`):
```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Frontend
    location / {
        root /var/www/detectiq;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/detectiq /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

5. **Set up SSL** (optional but recommended):
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### Option 4: DigitalOcean / Lightsail (Cheapest Cloud Option)

**DigitalOcean Droplet ($6/month):**
1. Create Ubuntu 22.04 droplet (1GB RAM, 1 vCPU)
2. Follow the same steps as AWS EC2 above
3. Point your domain to droplet IP

**AWS Lightsail ($5-10/month):**
1. Create Ubuntu instance
2. Open ports: 80, 443, 3001
3. Follow EC2 deployment steps

### Option 5: Kubernetes / Docker Swarm (Enterprise)

For high availability and auto-scaling:
- Use Helm charts (coming soon)
- Deploy Redis as StatefulSet
- Use Horizontal Pod Autoscaler for backend
- Use Ingress for routing

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
Currently, DetectIQ requires AWS Bedrock for AI features. **Coming soon:**
- Anthropic API direct support (alternative to Bedrock)
- Local LLM support (Ollama, LM Studio) - free but requires powerful hardware

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
**Absolutely!** Many companies use DetectIQ internally. The MIT License allows commercial use. Just make sure you:
- Use your own AWS credentials (don't share across teams)
- Review security best practices in [SECURITY.md](SECURITY.md)
- Consider setting up auth and RLS in Supabase for team use

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
