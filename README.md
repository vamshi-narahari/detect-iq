# DetectIQ v5.4

AI-powered detection engineering platform for SOC teams.

## Features
- ADS Builder — AI-powered detections with full Attack Detection Strategy output
- Query Translator — translate across 10 SIEM platforms
- Attack Simulator — realistic log generation
- Alert Triage — AI verdict engine
- Threat Intel — live CISA KEV + APT profiles
- MITRE ATT&CK Coverage — heatmap + honeycomb visualization
- Detection Autopilot — auto-draft detections from KEV feed

## Stack
- **Frontend**: React + Vite
- **Backend**: Node.js + Express
- **AI**: AWS Bedrock (Claude Sonnet)
- **Database**: Supabase
- **Cache**: Redis

## Setup

### Frontend
```bash
cd frontend
cp .env.example .env
# Fill in your Supabase credentials in .env
npm install
npm run dev
```

### Backend
```bash
cd backend
cp .env.example .env
# Fill in AWS, Redis, Resend credentials in .env
npm install
node server.js
```
