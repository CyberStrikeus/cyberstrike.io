---
name: owasp-wstg
description: OWASP Web Security Testing Guide v4.2 Checklist
tags: [web, owasp, security, testing]
version: "4.2"
---

# OWASP Web Security Testing Guide (WSTG) v4.2

## 1. Information Gathering (WSTG-INFO)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-INFO-01 | Search Engine Discovery | Use Google dorks, Shodan, Censys |
| WSTG-INFO-02 | Fingerprint Web Server | Identify server type and version |
| WSTG-INFO-03 | Review Webserver Metafiles | Check robots.txt, sitemap.xml |
| WSTG-INFO-04 | Enumerate Applications | Find subdomains and apps |
| WSTG-INFO-05 | Review Webpage Content | Comments, metadata, hidden fields |
| WSTG-INFO-06 | Identify Entry Points | Map all input vectors |
| WSTG-INFO-07 | Map Execution Paths | Understand application flow |
| WSTG-INFO-08 | Fingerprint Web Framework | Identify CMS, frameworks |
| WSTG-INFO-09 | Fingerprint Web Application | Version detection |
| WSTG-INFO-10 | Map Application Architecture | Understand infrastructure |

## 2. Configuration Testing (WSTG-CONF)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-CONF-01 | Network Infrastructure | Firewalls, load balancers |
| WSTG-CONF-02 | Application Platform | Server misconfigurations |
| WSTG-CONF-03 | File Extension Handling | Upload restrictions |
| WSTG-CONF-04 | Backup and Unreferenced Files | .bak, .old, .swp files |
| WSTG-CONF-05 | Infrastructure Interfaces | Admin panels |
| WSTG-CONF-06 | HTTP Methods | OPTIONS, TRACE, PUT |
| WSTG-CONF-07 | HTTP Strict Transport Security | HSTS header |
| WSTG-CONF-08 | RIA Cross Domain Policy | crossdomain.xml |
| WSTG-CONF-09 | File Permission | Sensitive file access |
| WSTG-CONF-10 | Subdomain Takeover | Dangling DNS records |
| WSTG-CONF-11 | Cloud Storage | S3, Azure Blob exposure |

## 3. Identity Management (WSTG-IDNT)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-IDNT-01 | Role Definitions | User role analysis |
| WSTG-IDNT-02 | User Registration | Registration flaws |
| WSTG-IDNT-03 | Account Provisioning | Account creation process |
| WSTG-IDNT-04 | Account Enumeration | Username discovery |
| WSTG-IDNT-05 | Weak Username Policy | Predictable usernames |

## 4. Authentication Testing (WSTG-ATHN)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-ATHN-01 | Credentials Transport | HTTPS, secure cookies |
| WSTG-ATHN-02 | Default Credentials | admin:admin, test:test |
| WSTG-ATHN-03 | Weak Lockout Mechanism | Brute force protection |
| WSTG-ATHN-04 | Bypassing Authentication | Logic flaws |
| WSTG-ATHN-05 | Remember Password | Insecure implementation |
| WSTG-ATHN-06 | Browser Cache Weakness | Cached credentials |
| WSTG-ATHN-07 | Weak Password Policy | Complexity requirements |
| WSTG-ATHN-08 | Security Question Weakness | Guessable answers |
| WSTG-ATHN-09 | Password Change Function | Flawed reset process |
| WSTG-ATHN-10 | Weaker Authentication | Fallback mechanisms |

## 5. Authorization Testing (WSTG-ATHZ)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-ATHZ-01 | Directory Traversal | Path traversal attacks |
| WSTG-ATHZ-02 | Bypassing Authorization | Privilege escalation |
| WSTG-ATHZ-03 | Privilege Escalation | Horizontal/vertical |
| WSTG-ATHZ-04 | IDOR | Insecure direct object reference |

## 6. Session Management (WSTG-SESS)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-SESS-01 | Session Management Schema | Token analysis |
| WSTG-SESS-02 | Cookie Attributes | Secure, HttpOnly, SameSite |
| WSTG-SESS-03 | Session Fixation | Pre-authentication tokens |
| WSTG-SESS-04 | Exposed Session Variables | URL, hidden fields |
| WSTG-SESS-05 | CSRF | Cross-site request forgery |
| WSTG-SESS-06 | Logout Functionality | Session termination |
| WSTG-SESS-07 | Session Timeout | Idle timeout |
| WSTG-SESS-08 | Session Puzzling | Variable overwrite |
| WSTG-SESS-09 | Session Hijacking | Token theft |

## 7. Input Validation Testing (WSTG-INPV)

| ID | Test Name | Description |
|----|-----------|-------------|
| WSTG-INPV-01 | Reflected XSS | Script injection |
| WSTG-INPV-02 | Stored XSS | Persistent injection |
| WSTG-INPV-03 | HTTP Verb Tampering | Method manipulation |
| WSTG-INPV-04 | HTTP Parameter Pollution | Duplicate parameters |
| WSTG-INPV-05 | SQL Injection | Database attacks |
| WSTG-INPV-06 | LDAP Injection | Directory attacks |
| WSTG-INPV-07 | XML Injection | XXE, XPath |
| WSTG-INPV-08 | SSI Injection | Server-side includes |
| WSTG-INPV-09 | XPath Injection | XML queries |
| WSTG-INPV-10 | IMAP/SMTP Injection | Email header injection |
| WSTG-INPV-11 | Code Injection | Remote code execution |
| WSTG-INPV-12 | Command Injection | OS command execution |
| WSTG-INPV-13 | Format String | printf vulnerabilities |
| WSTG-INPV-14 | Incubated Vulnerability | Delayed execution |
| WSTG-INPV-15 | HTTP Splitting | Response injection |
| WSTG-INPV-16 | HTTP Incoming Requests | Request smuggling |
| WSTG-INPV-17 | Host Header Injection | Virtual host attacks |
| WSTG-INPV-18 | SSTI | Server-side template injection |
| WSTG-INPV-19 | SSRF | Server-side request forgery |

## Testing Workflow

```
1. Reconnaissance (WSTG-INFO)
   ↓
2. Configuration Review (WSTG-CONF)
   ↓
3. Identity & Auth Testing (WSTG-IDNT, WSTG-ATHN)
   ↓
4. Authorization Testing (WSTG-ATHZ)
   ↓
5. Session Management (WSTG-SESS)
   ↓
6. Input Validation (WSTG-INPV)
   ↓
7. Documentation & Reporting
```

## Severity Rating (CVSS 3.1)

| Score | Severity | Example |
|-------|----------|---------|
| 9.0-10.0 | Critical | RCE, SQLi with admin access |
| 7.0-8.9 | High | Stored XSS, IDOR PII access |
| 4.0-6.9 | Medium | Reflected XSS, Info disclosure |
| 0.1-3.9 | Low | Missing headers, verbose errors |
