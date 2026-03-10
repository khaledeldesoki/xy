---
tags: [dashboard, bac, bugbounty, hub]
cssclass: dashboard
date: 2026-03-10
---

# 🔐 Broken Access Control — Bug Hunter HQ

> **OWASP #1 since 2021** · Category: Authorization · CVSS range: 4.0–9.8

---

## ⚡ Quick Launch

| 🚀 Action | 📍 Where |
|---|---|
| **New target** | Duplicate [[Target-Template]] → save to `09-Targets/` |
| **Daily log** | Duplicate [[Daily-Hunt-Log]] → open & fill |
| **Weekly review** | Duplicate [[Weekly-Review]] → reflect & plan |
| **Kanban board** | [[Hunting-Board]] |
| **Mid-test reference** | [[00-CHEATSHEET]] |
| **Submit a report** | [[Bug-Report-Template]] → then log in [[Findings-Database]] |
| **Learning queue** | [[Labs-Practice]] · [[Write-Ups]] |

---

## ✅ Open Tasks

```tasks
NOT DONE
path includes BAC-BugHunting
group by filename
limit 25
```

---

## 🗂 Vault Map — Theory (Know Your Enemy)

| Note                       | Core Concept                                                     | New? |
| -------------------------- | ---------------------------------------------------------------- | ---- |
| [[BAC-Overview]]           | Full taxonomy: all BAC types, attack patterns, surface checklist |      |
| [[IDOR]]                   | 10 IDOR types + hunting methodology (3-phase)                    |      |
| [[Horizontal-vs-Vertical]] | Lateral vs privilege climbing + combined attack patterns         |      |
| [[Forced-Browsing]]        | Admin panels, backup files, `.git` exposure, old API versions    | ✨    |
| [[JWT-Misconfiguration]]   | 8 vectors: alg:none, RS→HS, kid SQLi, jwk inject                 |      |
| [[API-BAC]]                | REST BOLA/BFLA, GraphQL introspection, batch abuse               |      |
| [[CORS-Misconfiguration]]  | Reflected origin, null, subdomain chain                          |      |
| [[Business-Logic-BAC]]     | Step-skip, race conditions, TOCTOU, state machines               |      |
| [[OAuth-SSO-BAC]]          | redirect_uri, state CSRF, PKCE bypass, SAML XSW                  | ✨    |

## ⚔️ Vault Map — Attack Techniques (How To Strike)

| Note | Core Concept | New? |
|---|---|---|
| [[IDOR-Techniques]] | 7 patterns: Autorize, chaining, blind IDOR, HPP | |
| [[Privilege-Escalation]] | Path probing, header bypass, role injection | |
| [[HTTP-Method-Abuse]] | Verb tampering, override headers, OPTIONS leak | |
| [[Mass-Assignment]] | All frameworks, field list, Arjun automation | |
| [[Parameter-Tampering]] | Hidden fields, debug flags, state + price manipulation | ✨ |
| [[Path-Traversal-BAC]] | Spring Boot `;`, nginx alias, URL encoding variants | ✨ |
| [[WebSocket-BAC]] | Per-message IDOR, subscription hijack, WS privesc | ✨ |
| [[Advanced-BAC-Chains]] | 5 critical chains, prototype pollution, smuggling | ✨ |

## 🔧 Vault Map — Tools & Methodology

| Note | What It Does |
|---|---|
| [[Tools-Arsenal]] | Decision matrix + one-liner recipes for every tool | ✨ |
| [[Burp-Suite-BAC]] | 8 extensions, Intruder templates, match-replace |
| [[Autorize-Plugin]] | Full multi-role setup + evidence export |
| [[Nuclei-BAC]] | 4 custom YAML templates + scan pipeline |
| [[Custom-Scripts]] | 5 Python/Bash scripts ready to run |
| [[Recon-Phase]] | JS parsing, GitHub, mobile APK, Swagger recon |
| [[Testing-Checklist]] | 70+ tasks across 9 phases (v3 — fully updated) | ✨ |
| [[Reporting-BAC]] | CVSS calc, impact escalation, PoC structure |
| [[Why-Reports-Fail]] | 8 mistakes that kill payouts — study before submitting | ✨ |

## 💣 Payloads & Resources

| Note | Contents |
|---|---|
| [[IDOR-Payloads]] | Numeric, UUID, encoded IDs, ffuf commands |
| [[Bypass-Payloads]] | Path, header, method, JWT, CORS, OAuth, WS, proto-pollution | ✨ |
| [[CVEs-BAC]] | 8 critical CVEs + bug bounty hall of fame table |
| [[Write-Ups]] | Write-up index + where to find more |
| [[Labs-Practice]] | PortSwigger, crAPI, HTB, TryHackMe — structured 3-week plan |
| [[Findings-Database]] | 📊 Live tracker — all bugs found, payout stats | ✨ |

---

## 📊 Active Targets

```dataview
TABLE
  program AS "Program",
  platform AS "Platform",
  status AS "Status",
  file.mtime AS "Last Active"
FROM "BAC-BugHunting/09-Targets"
WHERE status != null AND file.name != "Target-Template"
SORT file.mtime DESC
```

---

## 📈 Hunting Stats

```dataview
TABLE WITHOUT ID
  length(filter(rows, (r) => r.file.name)) AS "Total Notes",
  "Run [[Findings-Database]] for earnings stats" AS "Earnings"
FROM "BAC-BugHunting"
FLATTEN file AS rows
LIMIT 1
```

---

*v3 — Updated 2026-03-10 · [[00-GRAPH-INDEX]] · [[00-CHEATSHEET]] · [[Hunting-Board]]*
