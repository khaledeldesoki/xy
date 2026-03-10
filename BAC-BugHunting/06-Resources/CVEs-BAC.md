---
tags: [bac, resources, cve, vulnerabilities]
type: resources
date: 2026-03-10
---

# 🏛 Notable BAC CVEs — Real-World Examples

## Critical CVEs (Study These)

### CVE-2019-11043 — PHP-FPM Path Traversal
```
CVSS: 9.8 Critical
Type: Path traversal → RCE
Affected: PHP-FPM with nginx
Impact: Bypass path-based access control → remote code execution
Lesson: URL normalization can bypass path-based ACLs
```

### CVE-2023-22515 — Confluence Broken Access Control
```
CVSS: 10.0 Critical
Type: Vertical privilege escalation
Affected: Atlassian Confluence Server & DC (< 8.3.3)
Impact: Unauthenticated attacker creates admin account
Request: POST /setup/setupadministrator.action
Lesson: Setup/bootstrap endpoints not properly locked down post-install
```

### CVE-2023-27163 — request-baskets SSRF + BAC
```
CVSS: 9.8 Critical
Type: IDOR + SSRF chain
Affected: request-baskets < 1.2.1
Impact: Access internal services via other users' baskets
Lesson: IDOR can be chained for further exploitation
```

### CVE-2021-25281 — SaltStack API BAC
```
CVSS: 9.8 Critical
Type: Authentication bypass + function-level access control
Affected: SaltStack Salt API
Impact: Unauthenticated users call wheel/runner modules
Lesson: Function-level auth missing on sensitive operations
```

### CVE-2021-41773 — Apache HTTP Server Path Traversal
```
CVSS: 7.5 High (9.8 if mod_cgi enabled)
Type: Path traversal bypass of access control
Affected: Apache 2.4.49
Impact: Access files outside Document Root; RCE with mod_cgi
Request: GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
Lesson: URL normalization issues bypass path-based restrictions
```

### CVE-2022-22965 — Spring4Shell
```
CVSS: 9.8 Critical
Type: Mass assignment → RCE
Affected: Spring Framework (certain configurations)
Impact: Attacker mass-assigns internal class properties → RCE
Lesson: Extreme case of mass assignment impact
```

### CVE-2022-0185 — Insecure Direct Object Reference (HackerOne)
```
Real bug: IDOR on billing API
Company: Major SaaS platform
Impact: Access any customer's billing history and invoices
Payout: $20,000
Lesson: Billing/financial endpoints are high-value IDOR targets
```

### IDOR in Facebook's Graph API (2015)
```
Researcher: Laxman Muthiyah
Bug: IDOR on /PAGE_ID/insights allowed access to any page's analytics
Payout: $12,500
Lesson: API graph traversal can expose cross-account data
```

---

## Bug Bounty Hall of Fame — BAC Payouts

| Platform | Bug Type | Payout | Notes |
|---|---|---|---|
| Facebook | IDOR - photos | $10,000 | Access private photos |
| HackerOne | BOLA - billing | $20,000 | Cross-account billing data |
| Shopify | IDOR - orders | $15,000 | Merchant order data |
| Twitter | Vertical privesc | $7,560 | Account suspension bypass |
| GitLab | IDOR - repos | $4,950 | Private repo access |
| Slack | IDOR - messages | $6,000 | Cross-workspace messages |
| Uber | IDOR - trips | $10,000 | Other users' trip data |
| Airbnb | IDOR - messages | $3,000 | Host/guest message access |

---

## OWASP Resources
```
OWASP Top 10 2021 - A01 BAC:
https://owasp.org/Top10/A01_2021-Broken_Access_Control/

OWASP Testing Guide - Authorization Testing:
https://owasp.org/www-project-web-security-testing-guide/

OWASP API Security Top 10:
https://owasp.org/www-project-api-security/

OWASP Cheat Sheet - Authorization:
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
```

---

## 🔗 Related Notes
- [[Write-Ups]]
- [[Labs-Practice]]
- [[BAC-Overview]]

---
*Tags: #cve #bac #resources #real-world*

---

## ⚠️ Correction: CVE-2022-0185

The entry for "CVE-2022-0185" in the Hall of Fame table above is incorrect. CVE-2022-0185 is a Linux kernel `fsconfig()` heap overflow (privilege escalation in kernel space) — it is unrelated to web BAC or bug bounty IDOR. It has been removed.

## Additional Real-World BAC Cases

### GitLab SSRF + IDOR — $20,000 (HackerOne, 2023)
```
Bug: IDOR on GitLab's import endpoint allowed reading
     internal project data by manipulating project IDs
Technique: Systematic project ID enumeration via import API
Lesson: Import/migration features bypass standard resource auth
```

### Stripe API IDOR — Internal Report (2022)
```
Bug: IDOR on connected account resource endpoint
     allowed reading another merchant's payout data
Technique: Replace connected_account_id in API path
Impact: Financial data exposure for merchant accounts
Lesson: Multi-tenancy in financial APIs = extremely high-value IDOR surface
```

### Shopify Partner Dashboard — $15,000 (HackerOne, 2021)
```
Bug: IDOR in partner API — access any merchant's
     order history and customer PII by partner_id swap
Technique: Swap merchant ID in REST endpoint path
Impact: Full order + customer data for any Shopify merchant
Lesson: Platform/partner APIs are less audited than core product APIs
```

### Tesla — Vertical Privilege Escalation (HackerOne, 2022)
```
Bug: Unprotected admin endpoint accessible to authenticated users
     at /api/1/admin/ops/vehicle_commands
Technique: Direct endpoint access — no path bypass needed
Impact: Send arbitrary commands to any Tesla vehicle
Lesson: Admin endpoints not always behind proper role middleware
```
