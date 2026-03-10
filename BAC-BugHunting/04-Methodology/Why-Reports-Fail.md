---
tags: [bac, findings, mistakes, reports, rejected]
type: methodology
date: 2026-03-10
---

# ❌ Why BAC Reports Fail — Common Mistakes & Fixes

> Study this before submitting. These patterns kill payouts and get N/A'd.

---

## Mistake 1: Reporting Self-IDOR

**What happened**: You accessed your own resource from a second browser tab and called it an IDOR.

```
❌ "I can access /api/orders/1001 and see the order data."
(Order 1001 is YOURS)
```

**Fix**: You must prove **cross-account access**. You need two distinct accounts, and account A must access account B's resource using account A's credentials.

```
✅ Request uses Account A's token → returns Account B's data
← This is IDOR. Document both accounts clearly.
```

---

## Mistake 2: No Business Impact Statement

**What happened**: You wrote "I can read another user's data" and left it there.

Triage response: *"Low severity — user's name is not sensitive."*

**Fix**: Map the exposed data to real harm:

```
❌ "I can view another user's profile data."

✅ "I can access any user's profile, which exposes full name, 
   date of birth, phone number, and home address. Combined with 
   the password reset endpoint, this enables targeted phishing or 
   account takeover. This constitutes a GDPR Article 83 violation 
   with potential fines of up to 4% of global annual revenue."
```

---

## Mistake 3: Confusing PoC Steps

**What happened**: The triage team couldn't reproduce it. Closed as "Needs more info" → no response → auto-closed.

**Fix**: Write PoC like you're explaining it to someone who has never used the app:

```
✅ Step-by-step:
1. Register Account A: email=attacker@test.com, password=Pass123!
2. Register Account B: email=victim@test.com, password=Pass123!
3. Login as Account B. Create an order. Note the order ID from:
   GET /api/orders/me → {"orders":[{"id": 7845, ...}]}
4. Logout. Login as Account A. Copy Account A's Authorization header.
5. Send the following request:

   GET /api/orders/7845 HTTP/1.1
   Host: target.com
   Authorization: Bearer [ACCOUNT_A_JWT]

6. Response returns Account B's order details. ← IDOR confirmed.
```

---

## Mistake 4: Wrong Severity (Too High)

**What happened**: You rated a read-only IDOR on non-sensitive data as Critical. Triage immediately downgrades. You look inexperienced. They scrutinize your future reports more.

**CVSS guidance**:

| What You Found | Realistic Severity |
|---|---|
| Read-only IDOR on public username / bio | Low (3.5) |
| Read-only IDOR on order history (no PII) | Medium (5.3) |
| Read-only IDOR on email + phone + address | High (7.5) |
| Read-only IDOR on payment / card data | High (8.1) |
| Write / delete IDOR on user data | High (8.1) |
| IDOR chain leading to account takeover | Critical (9.8) |
| Unauthenticated admin access | Critical (9.8) |

---

## Mistake 5: Missing the Chain

**What happened**: You found a low-impact IDOR (just a username leak) and submitted it at Low. Triage accepts at $150.

Later, someone finds that same IDOR chains to a password reset takeover and gets $10,000.

**Fix**: Before submitting any IDOR, always check:
```
1. Does the IDOR endpoint expose a reset token / API key?
2. Can the leaked data (email) be used for targeted account takeover?
3. Does the endpoint allow WRITE (not just read)?
4. Can you chain this IDOR's data into another IDOR?
5. Is there a CORS misconfiguration that makes this remotely exploitable
   without user interaction? (Higher severity!)
```

---

## Mistake 6: Testing on Production Without Authorization

**What happened**: You used a real user's account (not a test account you own) as your "victim" account to prove cross-account access.

**Result**: Report accepted → but you've violated the program's rules → bounty withheld, possible ban.

**Fix**: Always create your own victim account. If you can't (invite-only app), note this in the report and use your two accounts + explain why real accounts would be affected.

---

## Mistake 7: Reporting Authorization Issues That Are "By Design"

**Examples**:
```
- Public user profiles are accessible by anyone ← intended
- Shared workspace members can see each other's files ← intended  
- Admin can see all users ← intended
```

**Fix**: Read the program's scope and product docs. If you're unsure, verify with a third account: if ANY user can access ANY other user's resource, it's a bug. If only workspace members can access workspace resources, it may be by design.

---

## Mistake 8: Not Checking if the Endpoint Existed Before

**What happened**: You find `/api/v1/export/all-users` accessible to any user. Submit as BFLA.

Triage: "This is a known issue, duplicate of report #99999."

**Fix**: Before submitting, check:
1. The program's disclosed reports (search "IDOR", "access control", endpoint path)
2. The program's changelog / patch notes
3. Whether the endpoint only exists in a recent deployment

---

## ✅ Pre-Submission Checklist

Before you hit submit, verify:

- [ ] Two accounts created and identified by me (not real users' data)
- [ ] Cross-account access demonstrated (not self-access)
- [ ] PoC reproducible by a stranger following only my steps
- [ ] Impact written in business terms, not just technical terms
- [ ] CVSS score honest and defensible
- [ ] Endpoint checked against program's disclosed reports (not a duplicate)
- [ ] Chain opportunities explored (ATO, financial, PII escalation)
- [ ] Report filed in [[Findings-Database]]

---

## 🔗 Related Notes
- [[Reporting-BAC]]
- [[Bug-Report-Template]]
- [[Advanced-BAC-Chains]]

---
*Tags: #mistakes #reports #methodology #bac*
