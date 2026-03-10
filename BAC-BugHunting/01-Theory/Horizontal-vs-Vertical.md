---
tags: [bac, theory, privilege-escalation, horizontal, vertical]
type: theory
severity: critical
owasp_ref: "A01:2021"
date: 2026-03-10
---

# ↕️ Horizontal vs Vertical Privilege Escalation

## The Core Distinction

```
HORIZONTAL Escalation:
  Same privilege level, different user
  User A  ──────────────→  User B's data
  (Lateral movement across accounts)

VERTICAL Escalation:
  Different privilege level, same or any user
  User ──────────────→  Admin functionality
  (Climbing the privilege hierarchy)

COMBINED (Most Dangerous):
  User A  →  User B's admin token  →  Full admin access
```

---

## 🔴 Vertical Privilege Escalation

### How It Happens
The application has role-based endpoints but fails to **enforce role checks server-side**, relying on:
- Hidden UI elements (admin buttons only shown to admins)
- Client-side role checks in JavaScript
- Security by obscurity (URL not advertised)

### Common Patterns

#### 1. Direct Admin Endpoint Access
```http
# Attacker (normal user) hits admin endpoint directly
GET /admin/users  → 200 OK (should be 403!)
POST /admin/deleteUser {"id": 9999}  → success
```

#### 2. Role Parameter Manipulation
```http
POST /api/register
{"username":"hacker","password":"pass","role":"admin"}
→ If role field is accepted: admin account created
```

#### 3. Mass Assignment to Elevate Role
```http
PUT /api/user/me
{"displayName": "hacker", "isAdmin": true}
→ isAdmin gets set if mass assignment present
```

#### 4. JWT Role Claim Tampering
```json
// Original JWT payload
{"sub":"user123","role":"user","exp":9999999}
// Tampered
{"sub":"user123","role":"admin","exp":9999999}
// If signature not properly verified: admin access
```

#### 5. Step-Up Auth Bypass
```http
# Endpoint requires /verify-2fa before /admin
# Skip /verify-2fa, directly hit /admin
# If server only checks session, not 2FA flag: bypass
```

#### 6. HTTP Method Override
```http
# POST /admin/action is blocked, but:
POST /admin/action
X-HTTP-Method-Override: GET
→ May bypass POST-specific restrictions
```

---

## 🔵 Horizontal Privilege Escalation

### How It Happens
Application uses **user-supplied reference** (ID, token, hash) to access another user's resource, without verifying the requesting user owns that resource.

### Common Patterns

#### 1. Direct ID Substitution (IDOR)
```http
GET /api/profile/1337  → returns attacker's profile
GET /api/profile/1338  → returns victim's profile (BUG)
```

#### 2. Account Takeover via Horizontal BAC
```http
POST /api/reset-password
{"user_id": 1338, "new_password": "hacked123"}
→ Resets victim's password
```

#### 3. Email/Username as Identifier
```http
GET /api/account?email=victim@example.com
→ Returns victim's account data
```

#### 4. Cross-Tenant Data Access (in SaaS)
```http
# User in Org A accessing Org B's data
GET /api/org/ORG_B_ID/employees
→ Should be 403, if org isolation fails: data leak
```

---

## 🟣 Combined Attack (Horizontal → Vertical)

This is the **most impactful** and often overlooked pattern:

```
1. Find IDOR on /api/user/{id}/api-key
   → Steal admin user's API key

2. Use admin API key
   → Full vertical privilege access

Example:
GET /api/user/1/export-token  → {"token": "admin_tok_xyz"}
Use token: Authorization: Bearer admin_tok_xyz
→ Full admin access achieved
```

---

## 🧪 Test Cases Matrix

| Test | Horizontal | Vertical |
|---|---|---|
| Access own resource | Baseline ✅ | Baseline ✅ |
| Access other user's resource (same role) | 🔴 IDOR if works | N/A |
| Access admin endpoint as user | N/A | 🔴 VertPrivEsc if works |
| Access other org's resource | 🔴 Tenant isolation fail | N/A |
| Create resource with elevated role | N/A | 🔴 if role accepted |
| Modify another user's resource | 🔴 IDOR | N/A |
| Delete another user's resource | 🔴 IDOR | N/A |

---

## Tasks
- [ ] #task Set up 3-tier test accounts: guest, user, admin
- [ ] #task Map all role-gated endpoints from JS files
- [ ] #task Test each endpoint from lower-privilege account
- [ ] #task Test horizontal access with 2 accounts same role
- [ ] #task Check mass assignment on all PUT/PATCH/POST endpoints
- [ ] #task Test JWT claim manipulation for vertical escalation

---

## 🔗 Related Notes
- [[IDOR]]
- [[JWT-Misconfiguration]]
- [[Mass-Assignment]]
- [[Privilege-Escalation]]

---
*Tags: #bac #horizontal #vertical #privilege-escalation*
