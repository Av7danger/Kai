# Bug Bounty Program - Example Corp Security Research

## Program Overview
Welcome to Example Corp's Bug Bounty Program. We appreciate security researchers who help us maintain the highest security standards.

## Target Scope

### In-Scope Domains
- example.com
- *.example.com
- api.example.com
- mobile.example.com
- admin.example.com
- staging.example.com
- test.example.com
- dev.example.com

### Subdomains
- mail.example.com
- blog.example.com
- shop.example.com
- secure.example.com
- vpn.example.com

### Web Applications
- https://example.com/app
- https://api.example.com/v1
- https://api.example.com/v2
- https://mobile.example.com/api

### IP Ranges
- 192.168.1.0/24
- 10.0.0.0/16
- 172.16.0.0/12

## Out-of-Scope
- example-test.net
- partners.example.org
- third-party.example.co.uk

## Reward Structure

### Critical Vulnerabilities ($5,000 - $15,000)
- Remote Code Execution (RCE)
- SQL Injection leading to data access
- Authentication Bypass
- Privilege Escalation

### High Vulnerabilities ($1,000 - $5,000)
- Cross-Site Scripting (XSS) in critical functions
- Server-Side Request Forgery (SSRF)
- Local File Inclusion (LFI)
- Directory Traversal with sensitive data access

### Medium Vulnerabilities ($200 - $1,000)
- Cross-Site Scripting (XSS) in non-critical functions
- Information Disclosure
- CSRF in important functions
- Subdomain Takeover

### Low Vulnerabilities ($50 - $200)
- Information Leakage
- Missing security headers
- CSRF in non-critical functions

## Program Rules

1. **Responsible Disclosure**: Report vulnerabilities through our secure portal
2. **No Disruption**: Do not disrupt our services or access user data
3. **Legal Compliance**: Only test on in-scope targets
4. **First Come, First Served**: Duplicate reports receive no reward

## Contact Information
- Security Team: security@example.com
- Bug Bounty Portal: https://bugbounty.example.com
- Emergency Contact: emergency-security@example.com

## Additional Information
- Program launched: January 2024
- Last updated: June 2025
- Total researchers: 500+
- Total payouts: $250,000+

### Technology Stack
- Frontend: React.js, Angular
- Backend: Node.js, Python (Django/Flask)
- Database: PostgreSQL, Redis
- Infrastructure: AWS, Docker, Kubernetes
- CDN: CloudFlare

### Special Notes
- Mobile applications are in scope
- API testing is encouraged
- Social engineering is out of scope
- Physical security testing is prohibited

## Testing Guidelines

### Allowed Testing Methods
- Automated scanning (rate-limited)
- Manual testing
- Social engineering simulation (with prior approval)
- Physical testing (with prior approval)

### Prohibited Activities
- DoS/DDoS attacks
- Spam or social engineering
- Physical attacks
- Testing on production data

### Rate Limiting
- Maximum 10 requests per second
- Maximum 1000 requests per hour
- Respect robots.txt

## Reporting Format

Please include the following in your reports:
1. **Vulnerability Type**: XSS, SQLi, etc.
2. **Affected Asset**: URL or component
3. **Severity Assessment**: Critical/High/Medium/Low
4. **Proof of Concept**: Steps to reproduce
5. **Impact**: Business impact description
6. **Remediation**: Suggested fix

## Legal Safe Harbor

Example Corp will not pursue legal action against researchers who:
- Act in good faith
- Report vulnerabilities responsibly
- Do not access, modify, or delete user data
- Do not disrupt services

---

*This document is confidential and proprietary to Example Corp. Unauthorized distribution is prohibited.*

Contact: security-team@example.com | Updated: June 28, 2025
