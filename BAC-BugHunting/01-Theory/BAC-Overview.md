---
tags: [bac, theory, owasp, overview]
type: theory
severity: critical
owasp_ref: "A01:2021"
date: 2026-03-10
version: 3
---

# 🔐 Broken Access Control — Complete Overview (v3)

## What Is It?
Access control enforces that users **cannot act outside their intended permissions**. When this fails — through missing checks, bypassable checks, or incorrectly implemented checks — it's Broken Access Control. Ranked **OWASP #1 since 2021**, appearing in **94% of tested applications**.

---

## 🧩 Complete BAC Classification Tree (v3)

```
Broken Access Control
│
├── 1. Vertical Privilege Escalation
│   ├── User → Admin role
│   ├── Unauthenticated → Authenticated
│   ├── Admin panel direct access (forced browsing)
│   ├── Role injection via registration / mass assignment
│   ├── JWT role claim tampering
│   └── HTTP method / path normalization bypass
│
├── 2. Horizontal Privilege Escalation (IDOR / BOLA)
│   ├── Numeric sequential IDOR (/api/order/1337 → 1338)
│   ├── UUID/GUID IDOR (leaked via other responses)
│   ├── Encoded ID IDOR (base64, MD5 decode/modify)
│   ├── IDOR via query string / JSON body / headers
│   ├── Nested resource IDOR (/users/VICTIM/payment-methods)
│   ├── File download IDOR (/export?report_id=)
│   └── Blind IDOR (write/delete — no response body)
│
├── 3. API-Level Authorization Failures
│   ├── REST BOLA (Broken Object Level Auth)
│   ├── REST BFLA (Broken Function Level Auth)
│   ├── GraphQL field-level over-exposure
│   ├── GraphQL introspection + BOLA
│   ├── GraphQL batch query enumeration
│   ├── gRPC missing auth interceptor per method
│   ├── gRPC metadata injection (role via gRPC headers)
│   ├── Old API version still accessible (v1 vs v2)
│   └── SOAP XXE combined with BAC bypass
│
├── 4. Token-Based BAC Failures
│   ├── JWT alg:none
│   ├── JWT RS256 → HS256 confusion
│   ├── JWT HMAC secret bruteforce
│   ├── JWT kid header path traversal / SQLi
│   ├── JWT jwk header injection
│   ├── OAuth redirect_uri manipulation
│   ├── OAuth state parameter CSRF
│   ├── OAuth scope escalation
│   ├── OAuth PKCE bypass
│   └── SAML signature wrapping (XSW)
│
├── 5. Forced Browsing & Information Exposure
│   ├── Admin panels (/admin, /management, /internal)
│   ├── Setup/install endpoints post-deployment
│   ├── Backup files (.bak, .env, .git exposure)
│   ├── Old API versions (/api/v0, /api/beta)
│   └── Predictable export URLs
│
├── 6. Business Logic & Workflow BAC
│   ├── Multi-step bypass (skip steps in checkout/verification)
│   ├── Object state manipulation (PENDING → PAID without payment)
│   ├── Referer-based access control (spoof header)
│   ├── Race conditions (TOCTOU, concurrent limit bypass)
│   ├── Feature flag bypass (?beta=true, ?internal=1)
│   └── Invite / share link without identity binding
│
├── 7. Cross-Origin BAC
│   ├── CORS reflected origin with credentials
│   ├── CORS null origin bypass
│   ├── Subdomain takeover → CORS origin trust
│   └── PostMessage origin bypass
│
├── 8. Parameter & Mass Assignment
│   ├── Mass assignment (isAdmin, role, plan, credits)
│   ├── Hidden form field manipulation
│   ├── Debug / feature flag parameter injection
│   ├── Price / quantity manipulation
│   └── HTTP method override
│
├── 9. Cloud & Serverless BAC
│   ├── AWS API Gateway Lambda authorizer wildcard policy
│   ├── Lambda function URL with auth=NONE
│   ├── S3 bucket public access (list/read/write)
│   ├── AWS Cognito unauthenticated identity pool
│   ├── GCP Cloud Function with public access
│   └── Azure APIM policy bypass on internal routes
│
├── 10. Protocol-Level BAC
│   ├── WebSocket per-message IDOR
│   ├── WebSocket subscription hijacking
│   ├── gRPC service reflection enumeration
│   └── HTTP request smuggling → ACL bypass
│
└── 11. Client-Side Access Control (Never Trust Client)
    ├── Hidden UI elements (remove display:none)
    ├── JavaScript role checks (edit in DevTools)
    ├── Cookie role manipulation (role=admin)
    └── localStorage/sessionStorage token tampering
```

---

## 📋 Core Vulnerability Patterns — Quick Reference

| Pattern | Example | Severity |
|---|---|---|
| IDOR — sequential ID | `/api/user/1337` → swap to `1338` | High |
| Vertical privesc — direct admin | Low-priv calls `DELETE /api/admin/user/9999` | Critical |
| JWT role tampering | `"role":"user"` → `"role":"admin"` | Critical |
| JWT alg:none | Remove signature, server accepts | Critical |
| Mass assignment | `{"isAdmin": true}` accepted | High |
| CORS + credentials | Attacker's origin reflects, credentials sent | High |
| Path normalization bypass | `/admin;/users` bypasses ACL | High |
| Header-based bypass | `X-Forwarded-For: 127.0.0.1` grants internal access | High |
| gRPC missing interceptor | Method callable without any token | High |
| Lambda URL auth=NONE | Serverless function fully public | Critical |
| Race condition limit bypass | 50× concurrent free trial activation | High |
| S3 public bucket | `aws s3 ls s3://target-backups --no-sign-request` | Critical |
| OAuth redirect_uri | Code redirected to attacker-controlled URL | Critical |
| GraphQL BOLA | `user(id: "victim_id")` returns their data | High |
| WebSocket IDOR | Swap resource ID in WS message | High |
| .env exposure | Database creds, JWT secret, API keys leaked | Critical |

---

## 🎯 Attack Surface Master Checklist

```
Authentication surface:
  □ Every JWT (Authorization header, cookies, responses, localStorage)
  □ Every session cookie (decode, inspect, tamper role fields)
  □ Every OAuth flow (map all 4 steps)
  □ Every SAML SSO integration

Object reference surface:
  □ Every URL path parameter containing an ID
  □ Every query string ID parameter (?id=, ?user=, ?doc=)
  □ Every JSON body ID field (post/put/patch bodies)
  □ Every file download / export URL
  □ Every WebSocket message with a resource reference

Role/permission surface:
  □ Every route with role-based rendering (admin links, premium features)
  □ Every /admin, /internal, /management, /staff path
  □ Every registration/profile-update endpoint (mass assignment)
  □ Every API function that modifies user roles or permissions

Protocol surface:
  □ All HTTP methods on every protected endpoint
  □ WebSocket traffic (DevTools → Network → WS)
  □ gRPC services (port scan 50051, 8080, 9090)
  □ All API versions (v0, v1, v2, beta, internal)

Cloud surface:
  □ S3 buckets named after the target domain
  □ API Gateway endpoints (unauthenticated access test)
  □ Lambda Function URLs in JS/mobile code
  □ Cognito identity pool IDs in JS/mobile code
```

---

## 🔗 Related Notes — All BAC Theory

[[IDOR]] · [[Horizontal-vs-Vertical]] · [[Forced-Browsing]] · [[JWT-Misconfiguration]]
[[API-BAC]] · [[gRPC-BAC]] · [[CORS-Misconfiguration]] · [[Business-Logic-BAC]]
[[OAuth-SSO-BAC]] · [[Cloud-Serverless-BAC]] · [[Testing-Checklist]]

---
*Tags: #bac #owasp #theory #overview · v3*
