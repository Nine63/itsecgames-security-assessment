# Security Vulnerability Assessment Report

**Target:** [http://www.itsecgames.com/](http://www.itsecgames.com/)

**Date:** September 2025

**Prepared By:** Chirayata Sarkar

**Role:** Security Officer Trainee (Assessment Task)

---

## 1. Executive Summary

The purpose of this assessment was to evaluate the security posture of the publicly hosted endpoint `http://www.itsecgames.com`.

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
* **Security Headers** for HSTS configuration checking

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

* **Grade:** T
* **Weaknesses:**
    * **Lack of Server Cipher Suite Preference:** The report indicates that the server has no preference for a specific cipher suite. This is a critical misconfiguration that allows the client to choose the weakest supported algorithm, overriding any secure ordering the server may have attempted.
    * **Use of Static RSA Key Exchange:** Many of the supported cipher suites (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`) use static RSA for key exchange. These suites do not provide **Forward Secrecy**. If the server's private key is ever compromised, an attacker can use it to decrypt all past recorded traffic that was encrypted using these cipher suites.
    * **Support for Weak CBC Ciphers:** The report explicitly flags multiple cipher suites as **WEAK**, including many that use Cipher Block Chaining (CBC) mode. This mode is susceptible to various attacks, such as padding oracle attacks (e.g., **POODLE** and **BEAST**), which can lead to information disclosure.
    * **Outdated/Weak Ciphers:** While the previous report mentioned 3DES/RC4, the provided list shows other weak ciphers are enabled, such as AES-128-CBC and all Camellia ciphers, which are marked as "WEAK".
    * **Missing HSTS Header:** As noted in the original assessment, the absence of the HTTP Strict Transport Security (HSTS) header leaves the website vulnerable to downgrade attacks and cookie hijacking.
    * **Outdated TLS Protocols:** The server still supports deprecated protocols such as TLS 1.0 and TLS 1.1. These versions contain known vulnerabilities and should be disabled in favor of TLS 1.2 and TLS 1.3.

---

### 3.4 Web Application & Header Issues

* Missing HTTP security headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security).
* Banner disclosure: Apache/PHP versions exposed in responses.
* Directory indexing enabled on some paths.

---

## 4. Risk Assessment

* **Critical Risks:**
    * **Untrusted/Invalid Certificate:** This is the most severe risk. An attacker can easily perform a **Man-in-the-Middle (MitM) attack** to intercept, read, and manipulate all user traffic, as a trusted secure connection cannot be established.
    * **Remote Code Execution (RCE) Vulnerabilities:** The outdated OpenSSH version contains multiple high-severity CVEs that allow an attacker to execute arbitrary code on the server from a remote location. In a production environment, this would lead to a complete system compromise and data breach.

* **High Risks:**
    * **Protocol Downgrade & Session Compromise:** The presence of the OpenSSH "Terrapin" vulnerability (CVE-2023-48795) and the lack of a server cipher preference could be exploited to force a protocol downgrade. This allows an attacker to manipulate the handshake process to use weaker, less secure cipher suites, which can then lead to a full session compromise.
    * **Exposure to Passive Decryption:** The server's support for static RSA key exchange (cipher suites that lack Forward Secrecy) means that any recorded encrypted traffic could be decrypted at a later date if the server's private key is ever compromised. This poses a long-term risk to the confidentiality of all past and future communications.

* **Medium Risks:**
    * **Web Application Flaws:** The website is vulnerable to various web-based attacks due to missing security headers. The lack of a **Content-Security-Policy (CSP)** header increases the risk of **Cross-Site Scripting (XSS)** and data injection attacks. The **Missing Anti-clickjacking Header** makes the site susceptible to **Clickjacking attacks**.
    * **Information Leakage & Privilege Escalation:** Outdated OpenSSH versions expose the server to various information disclosure and local privilege escalation vulnerabilities. While not as severe as RCE, these flaws allow an attacker who has gained initial access to move laterally within the system and elevate their privileges, potentially gaining full control.
    * **Padding Oracle Attacks:** The use of weak CBC-based cipher suites makes the server vulnerable to padding oracle attacks, such as **BEAST** or **POODLE**. These attacks could be used to decrypt small pieces of information, most notably session cookies, to hijack an authenticated user's session.

* **Low Risks:**
    * **Header and Banner Disclosure:** The lack of security headers and the exposure of server software versions (e.g., Apache/PHP) provides attackers with valuable reconnaissance information, making it easier for them to identify and target specific vulnerabilities.
    * **SSL Stripping:** The missing HSTS header allows an attacker to perform an **SSL Stripping attack**, tricking a user's browser into connecting over insecure HTTP, thereby bypassing all encryption.
    * **MIME-Sniffing:** The absence of the **X-Content-Type-Options** header allows older versions of browsers to perform MIME-sniffing, which could cause the browser to interpret the response body as a different content type.

---

## 5. Recommendations

This section outlines the prioritized remediation plan based on all identified vulnerabilities, including critical software flaws, SSL/TLS misconfigurations, and web application issues. The CVEs that each recommendation mitigates have been added for clarity.



### **5.1 Immediate Remediation**

These recommendations address the most critical and high-severity risks that could lead to a system compromise.

1.  **Obtain and Install a Trusted SSL/TLS Certificate:**
    * **Mitigates:** The risk of **Man-in-the-Middle (MitM) attacks**. This is the top priority as it establishes the fundamental trust required for a secure connection.

2.  **Upgrade OpenSSH to the Latest Stable Version (≥9.3p2):**
    * **Mitigates:**
        * **CVE-2023-38408:** Remote code execution via forwarded SSH agent requests.
        * **CVE-2023-48795:** Protocol downgrade and session compromise ("Terrapin" vulnerability).
        * **CVE-2023-51385:** Potential information disclosure and bypass flaws.
        * **CVE-2015-5600:** Weak keyboard-interactive authentication, enabling brute-force attacks.
        * **CVE-2016-0777, CVE-2016-0778, CVE-2016-1908, CVE-2016-6515, and CVE-2016-10009/10010/10011/10012:** Various privilege escalation, information leakage, and DoS vulnerabilities.

3.  **Disable Insecure TLS Protocols and Ciphers:**
    * **Mitigates:**
        * **TLS 1.0 and TLS 1.1 Support:** Protects against well-known vulnerabilities like **BEAST**, **POODLE**, and **CRIME**.
        * **Static RSA Ciphers:** Addresses the lack of **Forward Secrecy**, protecting past communications from future private key compromises.
        * **Weak CBC Ciphers:** Prevents **Padding Oracle attacks** (like POODLE and BEAST) that can be used to decrypt session cookies and other data.

### **5.2 Web Server Hardening**

These recommendations address the medium and low-severity risks that can facilitate attacks.

1.  **Implement Security Headers:**
    * **`Content-Security-Policy` (CSP):** Prevents **Cross-Site Scripting (XSS)** and other data injection attacks.
    * **`X-Frame-Options`:** Mitigates **Clickjacking attacks**.
    * **`Strict-Transport-Security` (HSTS):** Prevents **SSL Stripping attacks** by forcing the browser to use HTTPS.
    * **`X-Content-Type-Options: nosniff`:** Prevents **MIME-sniffing attacks** in older browsers.

2.  **Hide Server Banners:**
    * **Mitigates:** **Information Disclosure.** This makes it harder for attackers to identify the specific software and version, which they could use to find known exploits.

3.  **Disable Directory Listing:**
    * **Mitigates:** **Information Disclosure.** Prevents an attacker from browsing the file system and finding sensitive files or misconfigurations.

### **5.3 Ongoing Security Management**

1.  **Establish a Patch Management Process:**
    * **Mitigates:** The accumulation of all vulnerabilities, as seen in the report, including those related to outdated Windows patches, third-party software, and HP switch firmware. This is the most crucial long-term recommendation.

---

## 6. Conclusion

The assessment confirms that `http://www.itsecgames.com` hosts multiple vulnerabilities. In this context, the same misconfigurations and outdated OpenSSH versions exposes the system to **serious remote exploitation risks**.

**Immediate upgrades, configuration hardening, and a structured patch management process are strongly recommended.**



