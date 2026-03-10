---
tags: [index, graph, map, bac]
type: index
date: 2026-03-10
version: 4
---

# 🕸 Graph View Index — BAC Vault v4

## Graph View Color Legend (`.obsidian/graph.json` applied)

| Color | Tag | Node Type |
|---|---|---|
| 🔴 Red | `#dashboard` `#cheatsheet` | Entry points — open every session |
| ⬛ Black | `#theory` | Deep knowledge (11 notes) |
| 🟠 Orange | `#attack` | Exploitation techniques (9 notes) |
| 🔵 Blue | `#tools` | Tool guides (5 notes) |
| 🟢 Green | `#methodology` | Process & workflow (4 notes) |
| 🟣 Purple | `#payloads` `#resources` | Payloads + reference (9 notes) |
| 🟡 Yellow | `#template` | Templates (3 notes) |
| 🟤 Brown | `#target` | Active hunt logs (your files) |

---

## Complete File Tree — v4 Final (39 files)

```
📁 BAC-BugHunting/
│
├── ⚡ 00-CHEATSHEET.md              ← v2: gRPC, cloud, race condition added
├── 📊 00-DASHBOARD.md               ← Main hub, live Dataview queries
├── 🕸 00-GRAPH-INDEX.md             ← This file
│
├── 📁 01-Theory/                    (11 notes)
│   ├── BAC-Overview.md       ✨v3   ← Full 11-category classification tree
│   ├── IDOR.md                      ← 10 types, 3-phase methodology
│   ├── Horizontal-vs-Vertical.md    ← Priv escalation types + combined
│   ├── Forced-Browsing.md           ← Panels, backups, .git, old APIs
│   ├── JWT-Misconfiguration.md      ← 8 attack vectors
│   ├── API-BAC.md                   ← REST, GraphQL, SOAP
│   ├── CORS-Misconfiguration.md     ← Reflected, null, subdomain
│   ├── Business-Logic-BAC.md        ← Logic flaws, race, TOCTOU
│   ├── OAuth-SSO-BAC.md             ← OAuth/PKCE/SAML attacks
│   ├── gRPC-BAC.md           ✨NEW  ← Interceptor bypass, BOLA, metadata inject
│   └── Cloud-Serverless-BAC.md ✨NEW ← AWS/GCP/Azure serverless BAC
│
├── 📁 02-Attack-Techniques/         (9 notes)
│   ├── IDOR-Techniques.md           ← 7 patterns, chaining
│   ├── Privilege-Escalation.md      ← Path probe, header bypass
│   ├── HTTP-Method-Abuse.md         ← Verb tamper, override
│   ├── Mass-Assignment.md           ← All frameworks + Arjun
│   ├── Parameter-Tampering.md       ← Hidden fields, debug flags
│   ├── Path-Traversal-BAC.md        ← Spring Boot, nginx alias
│   ├── WebSocket-BAC.md             ← WS IDOR, subscription hijack
│   ├── Advanced-BAC-Chains.md ✨+3  ← 9 chains total (race, 2FA, .env)
│   └── Race-Condition-BAC.md  ✨NEW ← TOCTOU, double-spend, Turbo Intruder
│
├── 📁 03-Tools/                     (5 notes)
│   ├── Tools-Arsenal.md             ← Decision matrix + install one-liner
│   ├── Burp-Suite-BAC.md            ← 8 extensions, Intruder setup
│   ├── Autorize-Plugin.md           ← Full multi-role setup
│   ├── Nuclei-BAC.md                ← 4 custom YAML templates
│   └── Custom-Scripts.md     ✨v2   ← 6 scripts: rate-limited IDOR, race,
│                                       JWT suite, admin prober, CORS, GraphQL
│
├── 📁 04-Methodology/               (4 notes)
│   ├── Recon-Phase.md        ✨+3   ← +Cloud recon, Shodan dorks, gRPC scan
│   ├── Testing-Checklist.md  ✨+2   ← 11 phases, 90+ tasks (gRPC + cloud)
│   ├── Reporting-BAC.md             ← CVSS, impact escalation, PoC structure
│   └── Why-Reports-Fail.md          ← 8 mistakes + pre-submit checklist
│
├── 📁 05-Payloads/                  (2 notes)
│   ├── IDOR-Payloads.md             ← Numeric, UUID, encoded, ffuf commands
│   └── Bypass-Payloads.md           ← Path, JWT, CORS, OAuth, WS, proto-poll
│
├── 📁 06-Resources/                 (6 notes + findings/ subfolder)
│   ├── CVEs-BAC.md                  ← 8 critical CVEs + HoF payout table
│   ├── Write-Ups.md                 ← Write-up index + discovery tips
│   ├── Labs-Practice.md             ← PortSwigger, crAPI, HTB, TryHackMe
│   ├── Findings-Database.md  ✨FIXED ← Rebuilt: per-file architecture, 6 Dataview
│   ├── Defensive-Knowledge.md ✨NEW  ← RBAC/ABAC/ReBAC models + bypass logic
│   ├── BugBounty-Programs-Guide.md ✨NEW ← Platform comparison, program selection,
│   │                                       regulation-aware impact statements
│   └── findings/                   ← One .md file per bug (Dataview reads here)
│       └── (your finding files go here)
│
├── 📁 07-Kanban/                    (1 note)
│   └── Hunting-Board.md             ← 5-column board, phase-organized cards
│
├── 📁 08-Templates/                 (3 notes)
│   ├── Bug-Report-Template.md       ← H1/BBP-ready, CVSS included
│   ├── Daily-Hunt-Log.md            ← Templater daily log
│   └── Weekly-Review.md             ← Reflection + metrics + next-week plan
│
└── 📁 09-Targets/                   (template + your active targets)
    └── Target-Template.md           ← Per-program: accounts, IDs, checklist
```

---

## Hub Connection Map

```
                        ┌── IDOR ───── IDOR-Techniques ── Autorize
                        │        └─── IDOR-Payloads
                        │        └─── WebSocket-BAC
                        │        └─── Advanced-BAC-Chains (9 chains)
                        │
                        ├── Horizontal-vs-Vertical
                        │        └─── JWT-Misconfiguration
                        │        └─── Privilege-Escalation ─── Path-Traversal-BAC
                        │                                   └── HTTP-Method-Abuse
                        │
                        ├── API-BAC ────── Mass-Assignment
                        │           └──── Parameter-Tampering
                        │           └──── gRPC-BAC  ←────────────────── NEW
                        │
                        ├── Forced-Browsing
BAC-Overview ───────────┤
     │                  ├── JWT-Misconfiguration
     │                  ├── CORS-Misconfiguration
     │                  ├── Business-Logic-BAC ─── Race-Condition-BAC ← NEW
     │                  ├── OAuth-SSO-BAC
     │                  └── Cloud-Serverless-BAC ←────────────────────  NEW
     │
     └── Testing-Checklist (11 phases, 90+ tasks)
              ├── Recon-Phase ── +Shodan +Cloud +gRPC recon
              ├── Reporting-BAC ── Bug-Report-Template ── Findings-Database
              └── Why-Reports-Fail

Tools:    Tools-Arsenal ←→ Burp ←→ Autorize ←→ Nuclei ←→ Custom-Scripts (v2)
Resources: CVEs ←→ Write-Ups ←→ Labs ←→ Defensive-Knowledge ←→ BB-Programs-Guide
```

---
*v4 — 39 files · 2026-03-10*
