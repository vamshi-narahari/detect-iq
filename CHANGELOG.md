# Changelog

All notable changes to DetectIQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.5.0] - 2026-03-29

### 🎉 Open Source Release
- Published DetectIQ as open source under MIT License
- Added comprehensive documentation (README, CONTRIBUTING, SECURITY)
- Added GitHub issue templates for bugs and feature requests
- Updated .env.example files with detailed comments

### Added
- **Detection Chain Builder (N-stage)** - chain multiple detections across kill chain
  - Visual playbook generation with attack narratives
  - Smart MITRE ATT&CK tactic suggestions
  - Coverage gap analysis
  - Response playbook generation

- **Autopilot Multi-Source** - expanded from CVE-only to 4 sources:
  - CVE feed (CISA KEV catalog)
  - ATT&CK TTPs (20 curated techniques)
  - Threat Actors (8 APT groups)
  - Ransomware groups (6 major groups)

- **Atomic Red Team Integration**
  - Browse 50+ curated atomic tests
  - Generate matching detections automatically
  - View resolved command parameters

- **Log Replay (Dry-Run Testing)**
  - Test detections against real log samples before deployment
  - AI evaluates which log lines match detection logic
  - False positive identification

- **Defend Tools**
  - Honeytokens generator
  - DNS sinkhole configuration
  - Living Off the Land (LotL) detection coverage

- **Detection Health Monitor**
  - Quality scoring (0-100)
  - Blast radius estimation
  - False positive prediction
  - ML enhancement suggestions
  - SOAR workflow builder

- **SIEM Push Integration**
  - Direct push to 10 SIEM platforms
  - Audit logging for all deployments
  - Status tracking and error handling

- **Export Formats**
  - Sigma rule export
  - GitHub integration
  - Bulk import/export (JSON)

- **Team Collaboration**
  - Community detection sharing
  - Star/clone detections
  - Team invites
  - Detection versioning

### Fixed
- **413 Payload Too Large errors** - increased body limit to 500KB
- **JSON truncation errors** - increased max_tokens from 2500 to 4000+
- **Adversary SIEM payload trimming** - reduced log sample size before API call

### Changed
- Upgraded to Claude Sonnet 4.6 (from 3.5)
- Improved detection quality scoring algorithm
- Enhanced MITRE ATT&CK coverage visualization

### Technical
- Added BullMQ job queue for async AI processing
- Implemented Redis response caching
- Added jsonrepair for handling truncated AI responses
- Improved rate limiting with Redis backend
- Added compression middleware (gzip)

---

## [5.4.0] - 2026-03-28

### Added
- Initial detection chain builder (2-stage only)
- Basic autopilot with CVE feed
- Query translator for 10 SIEM platforms
- MITRE ATT&CK heatmap visualization
- Alert triage with AI verdict engine
- Adversary SIEM log generator

### Changed
- Migrated from Anthropic API to AWS Bedrock
- Updated UI design system

---

## Earlier Versions

See git commit history for earlier changes.

---

## Unreleased

Ideas for future releases:
- Detection versioning (git-like)
- Custom AI model support (local LLMs)
- Sigma rule import
- Threat hunting assistant
- Dark mode UI
- CLI tool for CI/CD
- Detection testing framework
- Jupyter notebook integration
