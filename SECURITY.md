# Security Policy

## Supported Versions

DetectIQ is currently in active development. We support the latest version with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.5.x   | :white_check_mark: |
| < 5.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in DetectIQ, please report it privately to help us fix it before public disclosure.

### How to Report

1. **Email**: Send details to the repository owner via GitHub private message or create a [Security Advisory](https://github.com/vamshi-narahari/detect-iq/security/advisories/new)

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days - we'll confirm if it's a vulnerability
- **Fix timeline**: We'll work on a fix and keep you updated
- **Disclosure**: We'll coordinate with you on public disclosure timing
- **Credit**: We'll acknowledge your contribution (unless you prefer to remain anonymous)

## Security Best Practices

When deploying DetectIQ in production:

### 1. Secrets Management
- **Never commit** `.env` files or AWS credentials to git
- Use environment variables or secrets managers (AWS Secrets Manager, HashiCorp Vault)
- Rotate AWS access keys regularly
- Use IAM roles instead of access keys when running on EC2

### 2. Network Security
- **Use HTTPS** in production (not HTTP)
- Configure restrictive CORS origins in `ALLOWED_ORIGINS`
- Run backend on localhost/internal network, expose only via reverse proxy
- Use security groups / firewall rules to restrict access

### 3. AWS Bedrock
- Apply **least-privilege IAM policies** - only allow `bedrock:InvokeModel` for required models
- Enable **AWS CloudTrail** to audit API calls
- Set **AWS Budgets** alerts to detect unusual usage patterns
- Use **VPC endpoints** for Bedrock (avoids internet routing)

### 4. Redis
- **Bind to localhost** (`bind 127.0.0.1` in redis.conf) if not using remote Redis
- **Use password auth** (`requirepass` in redis.conf) for remote Redis
- Enable **Redis ACLs** for fine-grained access control
- Consider **Redis over TLS** for production

### 5. Supabase
- Enable **Row Level Security (RLS)** policies (see README SQL migrations)
- Use `SUPABASE_ANON_KEY` in frontend (not service role key)
- Use `SUPABASE_SERVICE_ROLE_KEY` only in backend
- Regularly review **Supabase audit logs**

### 6. Rate Limiting
- Keep default rate limits in place (enforced by express-rate-limit)
- Monitor for abuse via audit logs
- Increase limits only if legitimate usage is being blocked

### 7. Input Validation
- DetectIQ sanitizes inputs before sending to Claude API
- If you modify the code, **always validate user input** before:
  - Passing to AI models
  - Executing as SIEM queries
  - Storing in database

### 8. Updates
- Keep dependencies up to date (`npm audit` and `npm update`)
- Subscribe to GitHub security advisories for this repo
- Monitor AWS Bedrock service updates

## Known Limitations

- **AI-generated queries**: DetectIQ generates SIEM queries using AI. Always **review queries** before deploying to production - AI can make mistakes or generate queries that don't match your environment.

- **No sandboxing**: Log Replay and Atomic Tests run queries in evaluation mode but don't execute them. Still, treat all user input as untrusted.

- **Shared state**: If multiple users share the same Supabase account, they can see each other's detections (by design). Use RLS policies to enforce isolation if needed.

## Security Contact

For urgent security issues, contact the maintainer via:
- GitHub: [@vamshi-narahari](https://github.com/vamshi-narahari)
- GitHub Security Advisory: [Create advisory](https://github.com/vamshi-narahari/detect-iq/security/advisories/new)

---

**Thank you for helping keep DetectIQ and its users safe!**
