---
tags: [bac, kanban, hunting, active]
kanban-plugin: board
date: 2026-03-10
---

## 🔭 Backlog — Not Started

- [ ] **[RECON]** Map all JS files → extract API endpoints #recon #bac
  `Tool: GAP (Burp) or: echo TARGET | gau | grep .js`

- [ ] **[RECON]** Discover Swagger / OpenAPI / api-docs endpoints #recon #api
  `ffuf -u TARGET/FUZZ -w api-docs-wordlist.txt -mc 200`

- [ ] **[RECON]** GitHub + Wayback Machine endpoint recon #recon #osint

- [ ] **[SETUP]** Create attacker + victim test accounts, collect all victim object IDs #setup #idor

- [ ] **[SETUP]** Log test account details in [[Target-Template]] #setup

- [ ] **[IDOR]** Run Autorize across full authenticated session #idor #tools

- [ ] **[IDOR]** IDOR fuzz on /api/orders/{id} endpoint (seq 1–10000) #idor #fuzzing

- [ ] **[IDOR]** IDOR fuzz on /api/invoices/{id} endpoint #idor #fuzzing

- [ ] **[IDOR]** IDOR on file download endpoint (/export, /download) #idor

- [ ] **[IDOR]** GraphQL introspection → BOLA test on all object queries #idor #graphql

- [ ] **[PRIVESC]** Admin panel discovery with feroxbuster + AdminPanels.txt #privesc #recon

- [ ] **[PRIVESC]** Test all admin endpoints as authenticated low-priv user #privesc

- [ ] **[PRIVESC]** Test header bypasses on every 403 response #privesc #bypass

- [ ] **[PRIVESC]** Registration endpoint mass assignment test #privesc #mass-assign

- [ ] **[JWT]** Decode all JWTs → test alg:none + RS256→HS256 #jwt #bypass

- [ ] **[JWT]** Brute-force HMAC secret (if HS256) #jwt

- [ ] **[CORS]** CORS reflected origin check on all /api/* endpoints #cors

- [ ] **[OAUTH]** Map OAuth flow → test redirect_uri manipulations #oauth

- [ ] **[WS]** Check for WebSocket traffic → IDOR on WS messages #websocket

- [ ] **[LOGIC]** Map all multi-step workflows → skip-step tests #logic


## 🔬 In Progress

- [ ] **[ACTIVE]** Currently testing: __________________ #active


## 🧪 Needs Manual Review

- [ ] **[REVIEW]** Autorize red-flagged responses — confirm manually #review #idor

- [ ] **[REVIEW]** Intruder hits with unusual response sizes — inspect #review

- [ ] **[REVIEW]** 403 responses with non-empty bodies — check for partial data #review

- [ ] **[REVIEW]** Mass assignment candidates — verify if field is reflected on re-fetch #review


## ✍️ Confirmed — Ready to Report

- [ ] **[REPORT]** Write clean PoC (attacker token + victim resource = victim data) #reporting

- [ ] **[REPORT]** Calculate CVSS score — use [[Reporting-BAC]] guide #reporting

- [ ] **[REPORT]** Draft report in [[Bug-Report-Template]] #reporting

- [ ] **[REPORT]** Check [[Why-Reports-Fail]] before submitting #reporting

- [ ] **[REPORT]** Log finding in [[Findings-Database]] #reporting


## ✅ Submitted / Closed

- [ ] **[DONE]** _Example: IDOR /api/orders/{id} — submitted H1 — awaiting triage_ #done


%% kanban:settings
```
{"kanban-plugin":"board","list-collapse":[false,false,false,false,false]}
```
%%
