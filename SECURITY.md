# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Stealth Compliance Monitor, please report it responsibly.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities through one of these methods:

1. **Email**: Send details to **[security@cognostra.com](mailto:security@cognostra.com)**
2. **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/Cognostra/Stealth-Compliance-Monitor/security/advisories/new)

### What to Include

To help us understand and address the issue quickly, please include:

- **Type of vulnerability** (e.g., RCE, XSS, SSRF, information disclosure)
- **Affected component** (service name, file path, endpoint)
- **Steps to reproduce** with clear, minimal instructions
- **Proof of concept** (code, screenshots, or video)
- **Potential impact** assessment
- **Suggested fix** (optional but appreciated)

### What to Expect

| Timeline | Action |
|----------|--------|
| **24 hours** | Acknowledgment of your report |
| **72 hours** | Initial assessment and severity classification |
| **7 days** | Detailed response with remediation plan |
| **30 days** | Target for fix release (critical issues faster) |

### Disclosure Policy

- We follow **coordinated disclosure** practices
- We will work with you to understand and validate the issue
- We will credit you in the security advisory (unless you prefer anonymity)
- We ask that you:
  - Give us reasonable time to address the issue before public disclosure
  - Avoid accessing or modifying user data
  - Act in good faith to avoid privacy violations and service disruption

## Security Best Practices for Users

### Environment Configuration

```bash
# Never commit .env files with real credentials
# Use environment variables in production

# Rotate API keys regularly
ZAP_API_KEY=<generate-unique-key>

# Restrict webhook URLs to trusted endpoints
WEBHOOK_URL=https://your-trusted-endpoint.com/webhook

# Enable HTTPS for all external communications
```

### Docker Security

```yaml
# docker-compose.yml best practices
services:
  scanner:
    # Run as non-root user
    user: "1000:1000"
    # Limit capabilities
    cap_drop:
      - ALL
    # Read-only filesystem where possible
    read_only: true
    # Resource limits
    deploy:
      resources:
        limits:
          memory: 2G
```

### Network Security

- Deploy ZAP proxy on an isolated network
- Use firewall rules to restrict proxy access
- Enable TLS for inter-service communication
- Regularly update Docker images

### Credential Management

- Use secrets management (HashiCorp Vault, AWS Secrets Manager)
- Rotate credentials after suspected exposure
- Use least-privilege principles for service accounts

## Security Features

Stealth Compliance Monitor includes built-in security features:

| Feature | Description |
|---------|-------------|
| **Secret Detection** | Scans for exposed API keys and credentials |
| **Dependency Scanning** | Identifies vulnerable npm packages |
| **SIEM Integration** | Forwards security events to your SIEM |
| **Audit Logging** | Tracks all scan activities |
| **Webhook Signatures** | HMAC-SHA256 signed webhook payloads |

## Known Security Considerations

### By Design

- **ZAP Proxy Access**: The tool requires network access to ZAP proxy. Ensure this is properly secured.
- **Target Site Access**: The scanner needs to access target URLs. Only scan sites you own or have permission to test.
- **AI Features**: When enabled, scan data may be sent to OpenAI. Review data privacy implications.

### Mitigations

- All external API calls use HTTPS
- Sensitive data is redacted from logs by default
- Reports can be encrypted before storage
- Rate limiting prevents abuse

## Security Audit History

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| TBD | Internal | Full codebase | Planned |

## Acknowledgments

We thank the following security researchers for responsibly disclosing vulnerabilities:

- *Be the first! Report a vulnerability to be listed here.*

---

## Contact

- **Security Team**: [security@cognostra.com](mailto:security@cognostra.com)
- **PGP Key**: Available upon request

Thank you for helping keep Stealth Compliance Monitor and its users safe! 🛡️
