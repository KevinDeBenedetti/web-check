# Security Policy

## ⚠️ Responsible Use

**Vigil is a security scanning toolkit intended for authorized security testing only.**

By using this tool, you agree to:

1. **Only scan systems you own** or have explicit written permission to test
2. **Comply with all applicable laws** and regulations
3. **Not use this tool for malicious purposes**

Unauthorized scanning of systems is illegal and unethical.

## 🔒 Reporting Security Vulnerabilities

If you discover a security vulnerability in Vigil itself, please:

1. **Do NOT open a public issue**
2. **Email the maintainer directly** with details
3. **Allow time for a fix** before public disclosure

### What to include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## 📋 Supported Versions

| Version | Supported |
| ------- | --------- |
| main    | ✅ Yes     |
| < main  | ❌ No      |

## 🛡️ Security Best Practices

When using Vigil:

1. **Keep Docker images updated:** `make install`
2. **Review scan results carefully** - automated tools can have false positives
3. **Secure your outputs** - scan results may contain sensitive information
4. **Use in isolated environments** when possible
5. **Don't commit scan results** to version control

## 📜 Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OF THIS TOOL OR DAMAGE CAUSED BY ITS USE.

Users are solely responsible for:
- Obtaining proper authorization before scanning
- Complying with all applicable laws
- Any consequences of using this tool
