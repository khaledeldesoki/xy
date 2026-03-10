---
tags: [template, bug-report, bac]
type: template
date: 2026-03-10
---

# 🐛 Bug Report Template — Broken Access Control

> **Instructions**: Fill in all sections. Delete N/A sections before submitting.

---

## Title
<!-- Format: [Bug Type] on [Endpoint] allows [Actor] to [Action] -->
**[IDOR/BAC/Privilege Escalation]** on `[endpoint]` allows **[role/unauth user]** to **[access/modify/delete]** **[resource belonging to another user/admin functionality]**

---

## Severity
- [ ] Critical (CVSS 9.0–10.0) — Unauthenticated OR leads to full account takeover
- [ ] High (CVSS 7.0–8.9) — Authenticated, access to sensitive PII/financial data
- [ ] Medium (CVSS 4.0–6.9) — Limited data exposure, no financial/PII impact
- [ ] Low (CVSS 1.0–3.9) — Minimal impact

**CVSS v3.1 Vector**: `AV: / AC: / PR: / UI: / S: / C: / H: / A:`
**CVSS Score**: 

---

## Summary
<!-- 2-3 sentences. What is the bug, where is it, what can an attacker do? -->



---

## Affected Endpoint(s)
```
Method: 
URL: 
Authentication required: Yes / No
Role required: 
```

---

## Vulnerability Details
<!-- Explain WHY this is a bug — missing ownership check, no role verification, etc. -->



---

## Impact
<!-- Be specific. What data is exposed? What actions can be performed? -->
- **Confidentiality**: 
- **Integrity**: 
- **Availability**: 
- **Business Impact**: 

---

## Proof of Concept

### Setup
```
Attacker Account:
  - Email: 
  - Role: 
  - Session/Token: (redact last 10 chars)

Victim Account:
  - Email: 
  - Role: 
  - Resource ID belonging to victim: 
```

### Steps to Reproduce
1. 
2. 
3. 

### Request (Attacker Accessing Victim's Resource)
```http
[METHOD] [PATH] HTTP/1.1
Host: [target]
Authorization: Bearer [ATTACKER_TOKEN]
Content-Type: application/json

[BODY IF APPLICABLE]
```

### Response (Showing Unauthorized Access)
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  [VICTIM'S DATA HERE]
}
```

### Expected Response
```http
HTTP/1.1 403 Forbidden
{"error": "Access denied"}
```

---

## Additional Evidence
<!-- Screenshots, video PoC, or additional requests -->



---

## Suggested Remediation
<!-- Be specific to the technology/framework used -->
1. 
2. 

---

## References
- OWASP A01:2021 — Broken Access Control
- CWE-284: Improper Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key

---

## Timeline
- **Discovered**: 
- **Submitted**: 
- **Triaged**: 
- **Fixed**: 
- **Bounty**: 

---
*Tags: #bug-report #bac #template*
