---
tags: [bac, resources, bugbounty, programs, platforms, strategy]
type: resources
date: 2026-03-10
---

# 💰 Bug Bounty Programs Guide — BAC Hunter's Playbook

> Operational intelligence. Which platforms, which programs, which targets give you the best ROI as a BAC specialist.

---

## Platform Comparison for BAC Hunters

| Platform | Best For | BAC Payout Range | Triage Speed | Notes |
|---|---|---|---|---|
| **HackerOne** | Large enterprise programs | $200–$25,000+ | 3–30 days | Largest program count, most BAC reports disclosed |
| **Bugcrowd** | Fintech, healthcare | $150–$15,000 | 5–45 days | Good BAC scope in regulated industries |
| **Intigriti** | European companies | €200–$15,000 | 2–14 days | GDPR context = higher BAC severity ratings |
| **Synack** | High-value private | $500–$50,000+ | 1–7 days | Invite-only, vetted hunters, less competition |
| **YesWeHack** | EU, French companies | €100–$10,000 | 3–21 days | Good for OAuth/SSO BAC (many EU SaaS) |
| **Private programs** | Direct company contact | Uncapped | Varies | Highest potential, requires reputation |

---

## Program Selection Criteria for BAC

### Tier 1: High BAC Potential
```
Look for programs with:
  ✓ "API" mentioned in scope (more BOLA/BFLA surface)
  ✓ Multi-tenant SaaS products (horizontal BAC goldmine)
  ✓ Marketplaces (buyer/seller role separation = BAC)
  ✓ Healthcare/fintech (PII/financial IDOR = higher severity)
  ✓ Recently launched (less time to audit = more bugs)
  ✓ Large scope (*.target.com vs target.com/specific-page)
  ✓ Mobile app in scope (mobile-only APIs often less tested)
  ✓ Critical/High bounties ≥ $3,000 for access control

Avoid (for BAC):
  ✗ Static sites, documentation sites
  ✗ Programs with "access control" in known-issue list
  ✗ Programs with tiny scope (no API surface)
  ✗ Programs that cap severity at Medium for auth issues
```

### Identifying Untested Programs

```
Signals of undertested programs:
  - New to the platform (< 6 months old)
  - Few or no disclosed reports (low hunter attention)
  - Recent major feature launch (new code = new bugs)
  - Recent acquisition (acquired company's APIs rarely reviewed)
  - App rewrite / v2 launch (old auth logic reimplemented fresh)
  - Expanding from one country to many (new regional APIs)

How to find them:
  - HackerOne: sort by "Recently updated" or "Newest"
  - Bugcrowd: filter by "New program"
  - Watch tech Twitter/LinkedIn for launch announcements
  - Follow acquisition news (Crunchbase, TechCrunch)
```

---

## Programs Known for Excellent BAC Payouts

### SaaS Platforms (High API Surface)
```
General patterns — not specific program names — that pay well:
  - Project management SaaS (multi-user workspaces = horizontal BAC)
  - E-commerce platforms (orders, payments, invoices = IDOR)
  - HR/Payroll SaaS (salary data IDOR = critical)
  - Healthcare apps (PHI/medical records = critical IDOR)
  - Financial services (transactions, accounts = critical)
  - Developer tools (API keys, repos, CI/CD secrets = critical)
  - Communication platforms (messages, channels = IDOR)
```

---

## BAC-Specific Hunting Strategy by Platform Type

### E-Commerce
```
Primary targets:
  /api/orders/{id}           ← IDOR → financial data
  /api/invoices/{id}         ← IDOR → payment info
  /api/users/{id}/addresses  ← IDOR → PII
  /api/users/{id}/cards      ← IDOR → payment methods
  /api/admin/orders          ← vertical privesc
  /api/admin/users           ← vertical privesc

Best CVSS outcomes:
  - IDOR on payment data → High (8.1)
  - IDOR + write (modify order, change shipping address) → High/Critical
  - Admin panel access → Critical
```

### SaaS / B2B
```
Primary targets:
  Multi-tenancy isolation:
    /api/org/{org_id}/data   ← cross-tenant IDOR
    /api/workspace/{ws_id}/  ← cross-workspace access
  
  User management:
    /api/admin/users         ← vertical privesc
    POST /api/users {role:admin} ← mass assignment

  Data exports:
    /api/export/{report_id}  ← IDOR on bulk export
    /api/analytics/{id}      ← IDOR on sensitive metrics

Best CVSS outcomes:
  - Cross-tenant IDOR = Critical (affects all customers)
  - Admin access = Critical
  - Data export IDOR with PII = High/Critical
```

### Healthcare / HIPAA
```
HIPAA violations escalate every BAC bug:
  - Any IDOR on patient data → HIPAA violation = Critical
  - PHI exposure per-record has defined legal penalties
  - Mention HIPAA in report → severity upgrade guaranteed

Targets:
  /api/patients/{id}
  /api/appointments/{id}
  /api/prescriptions/{id}
  /api/records/{id}/download
```

---

## Writing the Report for Maximum Payout

### Regulation-Aware Impact Statements

```
GDPR (EU users):
  "This vulnerability enables unauthorized access to personal data 
   of EU residents, constituting a reportable breach under GDPR 
   Article 33 within 72 hours of discovery. Fines may reach 
   €20M or 4% of global annual turnover (Article 83)."

HIPAA (US healthcare):
  "Unauthorized access to protected health information (PHI) 
   constitutes a HIPAA breach. Civil penalties: $100–$50,000 
   per violation, up to $1.9M per violation category per year."

CCPA (California):
  "This IDOR exposes personal information of California residents, 
   creating statutory damages of $100–$750 per consumer per incident 
   under CCPA Section 1798.150."

PCI-DSS (payment data):
  "Access to cardholder data outside PCI-DSS controlled systems 
   violates PCI-DSS Requirement 7. This may trigger mandatory 
   forensic investigation and potential loss of card processing ability."
```

---

## Managing Your Bug Bounty Operation

### Tracking & Metrics
```
Track per program:
  - Time invested (hours)
  - Bugs found
  - Bugs accepted
  - Bugs duplicated
  - Total earned
  - $/hour ratio

Good $/hour target: > $100/hr once experienced
If a program consistently gives duplicates: deprioritize it

Use [[Findings-Database]] for all tracking.
```

### Prioritization Framework
```
Score each program (1-5) on:
  1. API surface breadth       (many endpoints = many IDOR chances)
  2. Max payout for High/Crit  (is the upside worth it?)
  3. Competition level         (new vs. mature program)
  4. Data sensitivity          (healthcare > e-commerce > social)
  5. Response quality          (does triage understand BAC?)

Total score → allocate hunting hours proportionally
```

---

## Disclosure & After Submission

```
After submitting:
  1. Follow up politely after 14 days if no response
  2. After 30 days: escalate via platform dispute mechanism
  3. After 90 days with no fix: consider responsible public disclosure
     (check program's disclosure policy first)

If marked Duplicate:
  - Ask for the original report number
  - Check if scope/endpoint is exactly the same
  - If different endpoint/technique → dispute as new finding
  - If genuinely duplicate: still gives you proof-of-skill

If marked N/A or Informational:
  - Ask for specific reason
  - If disagree: provide additional impact evidence
  - Cite similar disclosed reports with higher severity
  - Calculate realistic attack scenario with cost estimate
```

---

## 🔗 Related Notes
- [[Reporting-BAC]]
- [[Why-Reports-Fail]]
- [[Findings-Database]]
- [[Bug-Report-Template]]

---
*Tags: #bugbounty #programs #platforms #strategy #bac*
