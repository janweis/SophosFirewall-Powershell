# Security Policy

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, please report it responsibly.

### Reporting Process

1. **Email** the project maintainer at jan.weis@it-explorations.de
2. **Subject line**: `[SECURITY] Brief description of vulnerability`
3. **Include**:
   - Type of vulnerability
   - Full paths of affected source file(s)
   - Location of affected code (tag/branch/commit)
   - Step-by-step instructions to reproduce
   - Proof-of-concept or exploit code (if possible)
   - Impact assessment
   - Suggested fix (if available)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Status updates**: Every 7 days until resolved
- **Fix timeline**: Depends on severity (critical: 7 days, high: 14 days, medium: 30 days)

### Disclosure Policy

- We follow **coordinated disclosure**
- Security advisories are published after a fix is available
- We request a **90-day embargo** before public disclosure
- Credit will be given to reporters (unless anonymity is requested)

## Security Best Practices

When using this module suite:

### Credentials

- **Never** hardcode credentials in scripts
- Use `Get-Credential` or secure credential stores
- Store connection context via `Connect-SfosFirewall` (credentials stored as SecureString)
- Clear sessions with `Disconnect-SfosFirewall` when done

### SSL/TLS Certificates

- **Production**: Always validate SSL certificates (do NOT use `-SkipCertificateCheck`)
- **Testing**: Use `-SkipCertificateCheck` only in isolated test environments
- **PowerShell 5.1**: Be aware that `-SkipCertificateCheck` affects all web requests in the session

### Input Validation

- All user input is automatically escaped via `ConvertTo-SfosXmlEscaped`
- Do not bypass XML escaping functions
- Validate input parameters with `[ValidateSet]`, `[ValidateLength]`, etc.

### Network Security

- Use encrypted connections (HTTPS) to firewalls
- Restrict network access to Sophos Firewall API (port 4444)
- Consider firewall rules to limit API access to authorized hosts
- Use strong administrator passwords

### Logging

- Review logs for unauthorized API access
- Monitor for unusual firewall configuration changes
- Use `-WhatIf` to preview changes before applying

## Known Security Considerations

### XML Injection

- **Mitigated**: All user input is escaped before XML embedding
- **Risk**: High if `ConvertTo-SfosXmlEscaped` is bypassed
- **Recommendation**: Always use provided helper functions

### Credential Storage

- **Mitigated**: Credentials stored as SecureString in module scope
- **Risk**: Medium - credentials exist in memory during session
- **Recommendation**: Use `Disconnect-SfosFirewall` to clear after use

### Certificate Validation (PowerShell 5.1)

- **Issue**: `-SkipCertificateCheck` sets global callback affecting all requests
- **Risk**: Medium - other web requests in same session may skip validation
- **Recommendation**: Upgrade to PowerShell 7+ or use dedicated sessions

## Security Contact

For security concerns, contact: jan.weis@it-explorations.de

---

Thank you for helping keep this project secure.
