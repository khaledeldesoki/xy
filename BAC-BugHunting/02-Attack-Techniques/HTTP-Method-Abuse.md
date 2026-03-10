---
tags: [bac, attack, http-methods, verb-tampering]
type: attack
severity: medium
date: 2026-03-10
---

# 🔄 HTTP Method Abuse & Verb Tampering

## Why Methods Matter for BAC
Access control is often implemented per-HTTP-method. Devs secure `POST /delete` but forget `DELETE /delete`, or secure `GET /admin` but forget `HEAD /admin`. Method override headers add another dimension.

---

## Method Matrix Testing
```
For every endpoint, test ALL methods:
GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, PROPFIND

Example endpoint: /api/admin/users

GET    /api/admin/users   → blocked? → also test:
POST   /api/admin/users   → blocked?
PUT    /api/admin/users   → blocked?
DELETE /api/admin/users   → blocked?
HEAD   /api/admin/users   → blocked? (HEAD returns only headers, may bypass auth)
OPTIONS /api/admin/users  → reveals allowed methods!
TRACE  /api/admin/users   → sometimes bypasses restrictions
```

---

## Method Override Headers
```http
# These headers tell intermediate proxies/frameworks to reinterpret the method
# Some backends honor them even when proxies strip them

POST /api/admin/deleteUser HTTP/1.1
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: DELETE
_method: DELETE        (form parameter, not header)

# Use case: endpoint blocks DELETE but honors POST + override header
```

## Practical Attack Scenarios
```http
# Scenario 1: GET-based CSRF via method confusion
# Server: "Only admins can DELETE /api/user/{id}"
# But GET /api/user/{id}/delete works without auth check:
GET /api/user/1337/delete → deletes user (no CSRF protection on GET!)

# Scenario 2: HEAD bypass for auth check
HEAD /admin/dashboard HTTP/1.1
→ If 200: endpoint exists and may be accessible
→ Burp: capture HEAD response with content (some servers return body on HEAD)

# Scenario 3: OPTIONS information leak
OPTIONS /api/admin/users HTTP/1.1
→ Response: Allow: GET, POST, PUT, DELETE
→ Reveals what's possible, then test each

# Scenario 4: TRACE XST (Cross-Site Tracing)
TRACE / HTTP/1.1
→ Server echoes request back including headers
→ If cookies in response → XST attack for cookie theft
```

---

## Burp Automation
```
1. Capture request to sensitive endpoint
2. Send to Intruder
3. Clear all payload markers
4. Add marker around HTTP method: §GET§ /api/admin
5. Payload list: GET POST PUT DELETE PATCH HEAD OPTIONS TRACE
6. Run attack
7. Filter: status != 405 (Method Not Allowed) and status != 403
```

---

## Tasks
- [ ] #task On every admin/sensitive endpoint, test all 8 HTTP methods
- [ ] #task Test method override headers on POST-protected endpoints
- [ ] #task Run OPTIONS on all endpoints to map allowed methods
- [ ] #task Look for GET-based state-changing actions (dangerous!)

---

## 🔗 Related Notes
- [[Privilege-Escalation]]
- [[Bypass-Payloads]]
- [[Testing-Checklist]]

---
*Tags: #http-methods #verb-tampering #bac #attack*
