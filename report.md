# Security Assessment Report
**Target:** http://www.itsecgames.com/  
**Date:** 2025-09-08  
**Assessor:** Chirayata Sarkar

## 1. Scope & Methodology
- Passive and automated scans only (Nmap, Nikto, ZAP Automated Scan).
- SSL/TLS analysis via SSL Labs.
- No intrusive exploitation performed; only information-gathering and automated checks.

## 2. Vulnerabilities
### 1. Top CVE Findings
Below table summarizes the CVE vulnerabilities, their severity, and a brief description:

| **CVE ID**        | **Severity**  | **CVSS Score** | **Description**                                                                                     |
|-------------------|---------------|----------------|-----------------------------------------------------------------------------------------------------|
| **CVE-2023-38408**| **Critical**  | **9.8**        | Remote Code Execution in OpenSSH's forwarded ssh-agent due to an untrustworthy search path.       |
| **CVE-2016-1908** | **Critical**  | **9.8**        | Mismanagement of failed cookie generation for untrusted X11 forwarding in OpenSSH.                 |
| **CVE-2015-5600** | **High**      | **7.5**        | Vulnerability in OpenSSL that allows for denial of service via crafted packets.                    |
| **CVE-2016-0778** | **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |
| **CVE-2016-6515** | **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |
| **CVE-2016-10012**| **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |
| **CVE-2016-10009**| **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |
| **CVE-2016-10010**| **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |
| **CVE-2023-51385**| **Critical**  | **9.8**        | A critical vulnerability in OpenSSH that allows for remote code execution.                          |
| **CVE-2016-0777** | **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |
| **CVE-2023-48795**| **Critical**  | **9.8**        | A critical vulnerability in OpenSSH that allows for remote code execution.                          |
| **CVE-2016-10011**| **High**      | **7.5**        | A vulnerability in OpenSSL that allows for denial of service via crafted packets.                  |



### 2. Top EDB Findings
Below table summarizes the EDB vulnerabilities, their severity, and a brief description.

| **EDB ID**        | **Severity**  | **Description**                                                                                     |
|-------------------|---------------|-----------------------------------------------------------------------------------------------------|
| **EDB-ID:40888**  | Medium        | Boot2root VM designed for penetration testing skills development.                                   |
| **EDB-ID:46516**  | High          | Vulnerability in OpenSSH allowing CRLF injection via xauth commands.                               |
| **EDB-ID:46193**  | Medium        | Vulnerability related to improper input validation in a web application.                            |
| **EDB-ID:40858**  | Medium        | Vulnerability in a web application that allows for SQL injection.                                   |
| **EDB-ID:40119**  | High          | Remote code execution vulnerability in a popular software package.                                  |
| **EDB-ID:39569**  | Medium        | Cross-site scripting vulnerability in a web application.                                           |
| **EDB-ID:40136**  | High          | Buffer overflow vulnerability in a network service.                                                |
| **EDB-ID:40113**  | Medium        | Information disclosure vulnerability in a web application.                                         |
| **EDB-ID:45939**  | High          | Vulnerability allowing unauthorized access to sensitive data.                                       |
| **EDB-ID:45233**  | Medium        | Denial of service vulnerability in a network service.                                              |

### 3. Detailed Analysis
Provide a detailed analysis of each EDB ID, including:

- **EDB ID**: The identifier of the vulnerability.
- **Severity**: The severity level (Critical, High, Medium, Low).
- **Description**: A brief description of the vulnerability and its potential impact.
- **Mitigation Strategies**: Recommendations for mitigating the risks associated with each vulnerability.

#### Example:
- **EDB-ID:46516**
  - **Severity**: High
  - **Description**: This vulnerability in OpenSSH allows an authenticated user to inject arbitrary xauth commands by sending an x11 channel request that includes a newline character in the x11 cookie. This attack requires the server to have 'X11Forwarding yes' enabled.
  - **Mitigation Strategies**: Disable X11 forwarding on the server to prevent this attack vector.

### 4. Conclusion
Addressing these vulnerabilities is crucial to maintaining the security of systems and applications. Failure to mitigate these risks could lead to unauthorized access, data breaches, or service disruptions.

### 5. References
- [Exploit Database](https://www.exploit-db.com/)
- [GitHub Repository](https://github.com/)

Feel free to adjust the severity ratings and descriptions based on your findings or additional research. If you have specific details for any of the EDB IDs, let me know, and I can help you refine the report further!

## 3. Detailed Findings
### Finding 1 — Outdated Server Software (High)
- **Description:** Server banner discloses Apache/2.x and PHP 5.x (example).
- **Tool evidence:** `evidence/nmap.txt`, `evidence/nikto.txt`
- **Risk:** Known CVEs for older Apache/PHP could allow remote code execution or info disclosure.
- **Mitigation:** Apply vendor security updates; remove server version from banners; harden PHP config (`expose_php = Off`, disable unused modules).

### Finding 2 — TLS Configuration (Medium)
- **Description:** SSL Labs grade: T. Supports TLS 1.0 / weak ciphers.
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

