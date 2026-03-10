---
tags: [target, active-hunt, template]
type: target-log
date: 2026-03-10
program: PROGRAM_NAME
platform: HackerOne / Bugcrowd / Intigriti / Private
status: active
---

# 🎯 Target: {{PROGRAM_NAME}}

## Program Info
| Field | Value |
|---|---|
| Platform | |
| Program URL | |
| Scope | |
| Out of Scope | |
| Max Severity | |
| Response Time | |
| Avg Bounty (High) | |

---

## Scope URLs
```
In Scope:
  - *.target.com
  - api.target.com
  - mobile.target.com

Out of Scope:
  - staging.target.com
  - *.dev.target.com
```

---

## Test Accounts

| Role | Email | Password | User ID | Session Token |
|---|---|---|---|---|
| Attacker (User) | | | | |
| Victim (User) | | | | |
| Admin (if obtained) | | | | |
| Guest | N/A | N/A | N/A | N/A |

---

## Victim's Object IDs (for IDOR testing)

| Resource Type | ID | Endpoint | Notes |
|---|---|---|---|
| Order | | /api/orders/ | |
| Invoice | | /api/invoices/ | |
| Message | | /api/messages/ | |
| File | | /api/files/ | |
| Report | | /api/reports/ | |
| Project | | /api/projects/ | |

---

## Endpoint Map

```
Discovered endpoints (from JS, Swagger, Burp sitemap):

GET  /api/users/me                    ← profile
GET  /api/users/{id}                  ← IDOR candidate
POST /api/users/{id}/update           ← mass assignment candidate
GET  /api/orders/{id}                 ← IDOR candidate
GET  /api/admin/                      ← privesc candidate
```

---

## Auth Mechanism
- [ ] Session cookie
- [ ] JWT (Header: Authorization: Bearer)
- [ ] API key
- [ ] OAuth 2.0 (provider: )
- [ ] SAML SSO

```
JWT Payload (decoded):
{
  
}
```

---

## Findings Log

### Finding #1 — [TITLE]
```
Type:
Endpoint:
Severity:
Status: [ ] Drafting  [ ] Submitted  [ ] Triaged  [ ] Resolved
CVSS:
Report URL:
Payout:
Notes:
```

### Finding #2 — [TITLE]
```
Type:
Endpoint:
Severity:
Status:
```

---

## Tested Checklist (this target)
- [ ] IDOR on all object endpoints
- [ ] Admin endpoint access (unauthenticated)
- [ ] Admin endpoint access (low-priv authenticated)
- [ ] Mass assignment on profile update
- [ ] JWT claim manipulation
- [ ] CORS reflected origin
- [ ] Path bypass on blocked endpoints
- [ ] HTTP method abuse
- [ ] WebSocket messages (if applicable)
- [ ] OAuth redirect_uri (if applicable)

---

## Notes & Observations


---

## Links
- Program page: 
- Swagger/API docs: 
- GitHub (if found): 
- Past disclosed reports: 

---
*Tags: #target #active-hunt*
