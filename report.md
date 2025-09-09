# Security Vulnerability Assessment Report

**Target:** [http://www.itsecgames.com/](http://www.itsecgames.com/)
**Date:** September 2025
**Prepared By:** Chirayata Sarkar
**Role:** Security Officer Trainee (Assessment Task)

---

## 1. Executive Summary

The purpose of this assessment was to evaluate the security posture of the publicly hosted endpoint `http://www.itsecgames.com`, which runs the intentionally vulnerable application **bWAPP**.

The scope included:

* Identifying vulnerabilities using publicly available tools (Nmap, Nikto, OWASP ZAP, SSL Labs).
* Assessing SSL/TLS configuration and certificate health.
* Highlighting misconfigurations and exposed information.

The analysis revealed multiple **critical and high severity vulnerabilities**, primarily due to an **outdated version of OpenSSH** with known **2023 CVEs** (remote code execution, protocol downgrade attacks, and information disclosure). In addition, several medium-severity issues from older OpenSSH versions (2015–2016) were also detected, including privilege escalation and information leakage flaws.

Overall, the site demonstrates an outdated and insecure configuration consistent with its training purpose. If this were a production environment, immediate remediation would be required.

---

## 2. Methodology

The following tools were used:

* **Nmap** with service/version detection and Vulners NSE script
* **Nikto** for web server misconfigurations
* **OWASP ZAP** for automated web vulnerability scanning and header analysis
* **SSL Labs** for TLS configuration and certificate testing
* **Wappalyzer** browser extension for technology fingerprinting

The assessment was **non-intrusive**: no manual exploitation was attempted. Only publicly available tools were used as per the assignment scope.

---

## 3. Findings

### 3.1 Critical & High Severity Vulnerabilities

| CVE ID         | Component          | Severity | Risk Summary                                           | Evidence           |
| -------------- | ------------------ | -------- | ------------------------------------------------------ | ------------------ |
| CVE-2023-38408 | OpenSSH <9.3       | High     | Remote code execution via forwarded SSH agent requests | `nmap-vulners.txt` |
| CVE-2023-48795 | OpenSSH (Terrapin) | High     | Protocol downgrade, session compromise                 | `nmap-vulners.txt` |
| CVE-2023-51385 | OpenSSH            | High     | Potential information disclosure / bypass              | `nmap-vulners.txt` |
| CVE-2015-5600  | OpenSSH            | High     | Weak keyboard-interactive auth → brute force possible  | `nmap-vulners.txt` |

---

### 3.2 Medium Severity Vulnerabilities

| CVE ID                                 | Component       | Severity | Risk Summary                                     | Evidence           |
| -------------------------------------- | --------------- | -------- | ------------------------------------------------ | ------------------ |
| CVE-2016-0777                          | OpenSSH roaming | Medium   | May leak private keys if roaming enabled         | `nmap-vulners.txt` |
| CVE-2016-0778                          | OpenSSH         | Medium   | Out-of-bounds read → DoS                         | `nmap-vulners.txt` |
| CVE-2016-1908                          | OpenSSH PKCS#11 | Medium   | Privilege escalation via improper cleanup        | `nmap-vulners.txt` |
| CVE-2016-6515                          | OpenSSH         | Medium   | Local privilege escalation (env var injection)   | `nmap-vulners.txt` |
| CVE-2016-10009 / 10010 / 10011 / 10012 | OpenSSH         | Medium   | Memory corruption / privilege escalation vectors | `nmap-vulners.txt` |

---

### 3.3 SSL/TLS Assessment

* **Grade:** \[Insert SSL Labs Grade Screenshot, e.g. “C”]
* **Weaknesses:**

  * TLS 1.0/1.1 supported
  * Weak ciphers (3DES, RC4) enabled
  * HSTS header missing

---

### 3.4 Web Application & Header Issues

* Missing HTTP security headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security).
* Banner disclosure: Apache/PHP versions exposed in responses.
* Directory indexing enabled on some paths.
* ZAP scan flagged insecure cookies (no HttpOnly / Secure flags).

---

## 4. Risk Assessment

* **Critical/High Risks:** Remote code execution and session compromise via outdated OpenSSH. These should be **remediated immediately** in a real environment.
* **Medium Risks:** Information leakage, local privilege escalation, and DoS risks highlight poor patch management.
* **Low Risks:** Missing headers and banner disclosure increase attacker reconnaissance capabilities but are less urgent.

---

## 5. Recommendations

### 5.1 Prioritized Remediation Plan

1. **Upgrade OpenSSH to Latest Stable Version (≥9.3p2)**

   * Resolves CVE-2023-38408, CVE-2023-48795, CVE-2023-51385, and legacy 2016 CVEs.
   * Disable agent forwarding and weak ciphers.

2. **Harden Authentication Mechanisms**

   * Mitigates CVE-2015-5600.
   * Implement MFA and enforce password lockouts.

3. **Disable Deprecated Features**

   * Remove “roaming” feature (CVE-2016-0777).
   * Patch memory corruption and DoS issues (CVE-2016-0778, CVE-2016-100xx).

4. **TLS Hardening**

   * Disable TLS 1.0/1.1.
   * Enforce TLS 1.2/1.3 only.
   * Add HSTS policy.

5. **Web Server Hardening**

   * Hide Apache/PHP version banners.
   * Disable directory listing.
   * Add CSP, X-Frame-Options, X-Content-Type-Options headers.

6. **Patch Management Process**

   * Establish continuous monitoring and regular patching to avoid accumulation of outdated software.

---

## 6. Conclusion

The assessment confirms that `http://www.itsecgames.com` hosts multiple vulnerabilities by design (as part of bWAPP). However, in a real-world context, the same misconfigurations and outdated OpenSSH versions would expose the system to **serious remote exploitation risks**.

**Immediate upgrades, configuration hardening, and a structured patch management process are strongly recommended.**



