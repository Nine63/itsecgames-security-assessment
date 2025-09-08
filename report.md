# Security Assessment Report
**Target:** http://www.itsecgames.com/  
**Date:** 2025-09-08  
**Assessor:** Chirayata Sarkar

## 1. Scope & Methodology
- Passive and automated scans only (Nmap, Nikto, ZAP quick scan).
- SSL/TLS analysis via SSL Labs.
- No intrusive exploitation performed; only information-gathering and automated checks.

## 2. Summary (Top findings)
| Priority | Finding | Evidence | Recommendation |
|---|---:|---|---|
| High | Outdated Apache/PHP versions disclosed — known CVE(s) possible | `evidence/nmap.txt`, `evidence/nikto.txt` | Upgrade Apache/PHP to patched versions and apply vendor patches. |
| Medium | Missing security HTTP headers (Content-Security-Policy, X-Frame-Options) | `evidence/zap-report.html`, `evidence/screenshot1.png` | Add CSP, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security headers. |
| Medium | Weak TLS configuration (TLS 1.0 enabled or weak ciphers) | `evidence/ssllabs.png` | Disable TLS <1.2 and weak ciphers; enable TLS 1.2/1.3 only. |
| Low | Directory listing / default files found | `evidence/nikto.txt` | Disable directory indexing; remove default files. |

*(Note: replace the rows above with actual findings from your scans.)*

## 3. Detailed Findings
### Finding 1 — Outdated Server Software (High)
- **Description:** Server banner discloses Apache/2.x and PHP 5.x (example).
- **Tool evidence:** `evidence/nmap.txt`, `evidence/nikto.txt`
- **Risk:** Known CVEs for older Apache/PHP could allow remote code execution or info disclosure.
- **Mitigation:** Apply vendor security updates; remove server version from banners; harden PHP config (`expose_php = Off`, disable unused modules).

### Finding 2 — TLS Configuration (Medium)
- **Description:** SSL Labs grade: [insert grade]. Supports TLS 1.0 / weak ciphers.
- **Evidence:** `evidence/ssllabs.png` and link to report.
- **Mitigation:** Disable TLS 1.0/1.1, remove RC4/3DES ciphers; enable TLS 1.2/1.3; enable HSTS.

### Finding 3 — Missing Security Headers (Medium)
- **Description:** Missing CSP, X-Frame-Options, X-Content-Type-Options.
- **Evidence:** `evidence/zap-report.html`
- **Mitigation:** Set headers in server config or app framework.

## 4. Tools & Commands Used
- `nmap -sV -Pn www.itsecgames.com -oN evidence/nmap.txt`
- `nikto -h http://www.itsecgames.com -output evidence/nikto.txt`
- OWASP ZAP Quick Scan → exported `evidence/zap-report.html`
- SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=www.itsecgames.com

## 5. Conclusion
- The site is intentionally vulnerable (bWAPP). The above findings are consistent with an intentionally vulnerable training site and should be remediated if deployed in production.

## 6. Appendix
- Raw outputs in `tool-outputs/` and screenshots in `evidence/`.

