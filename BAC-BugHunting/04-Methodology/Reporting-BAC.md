---
tags: [bac, methodology, reporting, writeup]
type: methodology
date: 2026-03-10
---

# 📄 Reporting BAC Vulnerabilities — Writing Impactful Reports

## Why BAC Reports Get Triaged Down
The #1 reason IDOR/BAC reports get low payouts or N/A:
1. **No clear impact** — "I can view another user's data" isn't enough
2. **Confusing PoC** — triage can't reproduce it
3. **Missing auth context** — didn't clearly show which role found the bug
4. **Understated severity** — didn't show the real business impact

---

## Report Structure

### 1. Title
```
❌ Bad: "IDOR vulnerability found"
✅ Good: "IDOR on /api/orders/{id} allows any authenticated user to 
          access, modify, and delete any other user's orders"
✅ Great: "Unauthenticated IDOR on /api/v2/documents/{id} exposes 
           all customer PII including SSN, DOB, and payment methods"
```

### 2. Severity + CVSS
```
CVSS v3.1 for IDOR (High):
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N → 8.1 (High)
  AV:N  - Network exploitable
  AC:L  - Low complexity
  PR:L  - Low privilege (authenticated)
  UI:N  - No user interaction
  C:H   - High confidentiality impact
  I:H   - High integrity impact (if write IDOR)
  A:N   - No availability impact

For unauthenticated IDOR → PR:N → 9.1 (Critical)
For admin takeover via IDOR chain → 9.8 (Critical)
```

### 3. Summary (2-3 sentences max)
```
"The /api/v1/invoices/{invoice_id} endpoint does not verify that the 
requesting user owns the invoice. An authenticated attacker can enumerate 
invoice IDs to access any other user's invoice data, including billing 
address, payment method details, and purchase history."
```

### 4. Impact (Be Specific & Business-Focused)
```
- Full PII exposure for all [X million] users
- Financial data leakage (payment methods, transaction history)
- Account takeover potential via password reset token theft
- GDPR/CCPA violation risk with regulatory penalties
- Competitive intelligence leak (business plans, contracts)
- Reputational damage from data breach disclosure
```

### 5. Proof of Concept (Crystal Clear Steps)
```
Prerequisites:
- Account A (attacker): test@attacker.com / Pass123
- Account B (victim): victim@example.com / Pass123
- Account B creates invoice #7845

Step 1: Login as Account A
Step 2: Send the following request:

  GET /api/v1/invoices/7845 HTTP/1.1
  Host: target.com
  Authorization: Bearer [Account A's token]

Response (200 OK):
  {
    "invoice_id": 7845,
    "user": "victim@example.com",   ← Account B's email
    "amount": 299.00,
    "card_last4": "4242",
    "billing_address": "123 Main St, NYC"
  }

Expected behavior: 403 Forbidden
Actual behavior: Returns Account B's invoice data to Account A
```

### 6. Remediation
```
Specific and actionable:

"Implement ownership verification before returning invoice data:

// Before:
Invoice inv = db.getInvoice(invoiceId);
return inv;

// After:
Invoice inv = db.getInvoice(invoiceId);
if (inv.getUserId() != currentUser.getId()) {
    throw new ForbiddenException();
}
return inv;

Additionally, consider using indirect references (opaque tokens mapped 
server-side) instead of sequential integer IDs to prevent enumeration."
```

---

## Severity Escalation Strategies

```
Make your BAC report higher severity by demonstrating chains:

Chain 1: READ IDOR → PII Leak
  → Reference GDPR penalties ($20M or 4% global revenue)

Chain 2: WRITE IDOR → Data Tampering
  → Show you can modify victim's data

Chain 3: DELETE IDOR → Data Destruction
  → Show you can delete victim's resources

Chain 4: IDOR → Account Takeover
  → GET /api/user/{id}/reset-token → use token to reset password

Chain 5: Low-Impact IDOR → High-Impact IDOR
  → IDOR on innocuous endpoint leaks IDs usable for critical IDOR
```

---

## Duplicate Prevention
```
Before submitting:
1. Search program's disclosed reports for "IDOR", "access control"
2. Check if the specific endpoint was previously reported
3. Check BBOT/Shodan for similar vulnerable instances
4. Test on production (not staging) — different fix states

If it's a duplicate:
- Ask for collaboration credit
- Find a higher-impact variant of the same bug
```

---

## 🔗 Related Notes
- [[Bug-Report-Template]]
- [[Testing-Checklist]]
- [[CVEs-BAC]]

---
*Tags: #reporting #bac #methodology #bugbounty*
