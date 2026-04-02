# Security Checklist for DetectIQ

Use this checklist before deploying DetectIQ or making repository public.

## ✅ Repository Security

### Before Making Repository Public
- [ ] Run `git log --all -- "*/.env"` to ensure no .env files in history
- [ ] Run `grep -r "AKIA" .` to check for AWS credentials
- [ ] Run `grep -r "ghp_" .` to check for GitHub tokens
- [ ] Verify `.gitignore` includes `.env` and `dist/`
- [ ] Check no IP addresses or domains in code (use environment variables)
- [ ] Review all committed files: `git ls-files`

### Ongoing
- [ ] Never commit `.env` files
- [ ] Never hardcode credentials in code
- [ ] Use environment variables for all secrets
- [ ] Rotate credentials if accidentally exposed
- [ ] Enable GitHub secret scanning (Settings → Security → Secret scanning)
- [ ] Enable Dependabot alerts (Settings → Security → Dependabot)

## ✅ AWS Security

### IAM Best Practices
- [ ] Create dedicated IAM user for DetectIQ (not root account)
- [ ] Apply principle of least privilege (only `bedrock:InvokeModel`)
- [ ] Enable MFA on AWS account
- [ ] Rotate access keys every 90 days
- [ ] Never share credentials between environments

### Bedrock Configuration
- [ ] Only enable required models (Claude Sonnet 4.6)
- [ ] Set up CloudWatch alarms for high usage
- [ ] Enable CloudTrail logging for Bedrock API calls
- [ ] Set AWS Budget alerts ($100/month threshold)

## ✅ Deployment Security

### Server Hardening
- [ ] Keep OS updated: `sudo apt update && sudo apt upgrade`
- [ ] Configure firewall: `sudo ufw enable`
- [ ] Disable password SSH login (use keys only)
- [ ] Run services as non-root user
- [ ] Enable automatic security updates

### Application Security
- [ ] Use HTTPS only (no HTTP in production)
- [ ] Enable rate limiting (already in backend)
- [ ] Set strong CORS policies (restrict origins)
- [ ] Keep dependencies updated: `npm audit fix`
- [ ] Use PM2 with proper process limits
- [ ] Configure nginx with security headers (already done with Helmet)

### Network Security
- [ ] Restrict server access to company IPs only (for internal deployments)
- [ ] Use Cloudflare for DDoS protection (for public deployments)
- [ ] Close unused ports: only 80, 443, 22
- [ ] Use VPC/private subnets (for cloud deployments)

## ✅ Credential Management

### What Should NEVER Be Committed
- ❌ `.env` files
- ❌ AWS access keys / secret keys
- ❌ GitHub personal access tokens
- ❌ Supabase service role keys (anon key is okay)
- ❌ Resend API keys
- ❌ Private keys (.pem, .key files)
- ❌ Database credentials
- ❌ API keys / tokens

### What Can Be Committed (Public)
- ✅ `.env.example` files (with placeholder values)
- ✅ Supabase project URL (public by design)
- ✅ Supabase anon key (public by design)
- ✅ GitHub repository URLs
- ✅ Documentation
- ✅ Source code

### If Credentials Are Exposed
1. **Immediately rotate** all exposed credentials
2. **Check AWS CloudTrail** for unauthorized usage
3. **Revoke old credentials** in AWS/GitHub/Supabase
4. **Generate new credentials**
5. **Update all services** with new credentials
6. **Consider using git-filter-repo** to remove from history:
   ```bash
   git filter-repo --path .env --invert-paths
   ```

## ✅ Monitoring & Auditing

### Set Up Alerts
- [ ] AWS Budgets alert at $50, $100, $150
- [ ] CloudWatch alarm for high Bedrock API usage
- [ ] GitHub secret scanning alerts enabled
- [ ] Dependabot security alerts enabled
- [ ] Server disk space monitoring (>80% alert)
- [ ] PM2 process monitoring

### Regular Audits (Monthly)
- [ ] Review AWS CloudTrail logs
- [ ] Check `npm audit` for vulnerabilities
- [ ] Review nginx access logs for suspicious activity
- [ ] Check Redis memory usage
- [ ] Review GitHub audit log (Settings → Audit log)
- [ ] Verify no new .env files committed: `git log --all -- "*/.env"`

## ✅ Incident Response

### If Security Breach Detected
1. **Isolate** - Stop services immediately
2. **Assess** - Identify what was compromised
3. **Rotate** - Change all credentials
4. **Patch** - Fix vulnerability
5. **Monitor** - Watch for further activity
6. **Document** - Record incident for review

### Emergency Contacts
- AWS Support: https://console.aws.amazon.com/support/
- GitHub Support: https://support.github.com/
- Supabase Support: https://supabase.com/support

---

## 🔍 Quick Security Scan

Run these commands before making repository public:

```bash
# Check for AWS credentials
grep -r "AKIA[0-9A-Z]\{16\}" . --exclude-dir=node_modules --exclude-dir=.git

# Check for GitHub tokens
grep -r "ghp_[0-9a-zA-Z]\{36\}" . --exclude-dir=node_modules --exclude-dir=.git

# Check for committed .env files
git ls-files | grep -E "\.env$|\.env\."

# Check for sensitive strings
grep -r "password\|secret\|token" . --include="*.js" --include="*.jsx" --exclude-dir=node_modules | grep -v "process.env"

# Verify .gitignore is working
git status --ignored | grep ".env"
```

If any of these return results (except the .gitignore check), **DO NOT make repository public** until fixed.

---

**Last Updated**: 2026-03-29
**Next Review**: Every month before major releases
