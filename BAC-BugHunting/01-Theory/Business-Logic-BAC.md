---
tags: [bac, theory, business-logic, logic-flaw]
type: theory
severity: high
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🧠 Business Logic BAC Flaws

## What Makes These Different
Logic-based BAC flaws are **not about missing auth checks**. They arise when the application's workflow logic can be manipulated to bypass access controls. Automated scanners miss these entirely — only manual testing finds them.

---

## Pattern 1: Multi-Step Process Bypass

```
Normal flow:  Step1 → Step2 → Step3 (privileged action)
Attack:       Skip Step1, Step2 → POST directly to Step3
```

```http
# Step 3 assumes Step 1 (payment verification) already happened:
POST /checkout/step3/confirm
{"order_id": "1337", "confirmed": true}
→ Order confirmed without payment
```

**Testing approach**: Map every multi-step flow. For each flow, try accessing the final step URL directly without completing earlier steps. Check if the server validates that prior steps were completed, or just trusts the session state.

---

## Pattern 2: Race Condition on Access Control (TOCTOU)

Race conditions in BAC occur when the **check** and the **use** are not atomic. Between "is this user allowed?" and "perform the action", another request can slip through.

```
Timeline:
  t=0ms  Request A: check → allowed (limit not reached yet)
  t=1ms  Request B: check → allowed (limit not reached yet)
  t=5ms  Request A: use  → action performed
  t=6ms  Request B: use  → action performed (limit bypassed!)
```

**Testing**: Use Burp Suite's HTTP/2 single-packet attack for maximum precision:
```
Repeater → duplicate tab ×20 → "Send group in parallel (last-byte sync)"
```

Or use the async Python tester from [[Race-Condition-BAC]] — do **not** use `threading.Thread` + synchronous `requests`, which staggers requests due to Python's GIL and will not reliably trigger the race window.

**High-value targets**: trial activations, coupon codes, limit-once-per-account actions, balance debits, subscription upgrades.

---

## Pattern 3: Price / Value Manipulation

```http
POST /api/purchase
{"item_id": "premium_plan", "price": 0.01}
→ If price is accepted from the client: free premium
```

```http
POST /api/cart/checkout
{"cart_id": "abc123", "total": 0.01}   ← override total
{"discount_percent": 100}               ← 100% discount
```

---

## Pattern 4: Object State Manipulation

Applications use state machines (PENDING → PAID → SHIPPED). If state transitions aren't enforced server-side, you can force invalid transitions:

```http
# An order in SHIPPED state should be immutable to users
# Attack: force it back to PENDING so you can "cancel + refund"
PATCH /api/order/1337 {"status": "PENDING"}

# Or: skip the PENDING → PAID transition entirely:
PATCH /api/order/1337 {"payment_status": "paid", "status": "processing"}
```

---

## Pattern 5: Referer / Origin-Based Access

```http
# Admin action checks Referer header to confirm it came from admin page:
GET /admin/action HTTP/1.1
Referer: https://target.com/admin/dashboard
→ Add this header to any request from a non-admin context
```

---

## Pattern 6: TOCTOU — Time-of-Check vs. Time-of-Use (Session)

```
1. CHECK: User's subscription is verified as active → session flag set
2. ACTION: Cancel the subscription in another tab
3. USE: Access premium feature using the now-stale session flag
→ Feature still accessible because the flag was set during step 1
```

---

## Pattern 7: Account Context / Role Context Switching

```http
# Apps with personal/business/admin contexts
POST /api/context/switch {"context": "business_admin"}
→ If context switch isn't properly validated: get business_admin privileges

# Or: include context param on requests that don't expect it
GET /api/data?context=admin
POST /api/action {"user_context": "staff"}
```

---

## Pattern 8: Invite / Share Link Abuse

```
Admin generates invite link for User A.
User A shares the link with User B.
Link grants elevated access to B as well.
→ If invite isn't bound to a specific identity or is not single-use
```

Test: After accepting an invite, does the same link still work for other accounts?

---

## Where to Look

```
Multi-step workflows:
  Checkout flows, account verification, password reset,
  2FA enrollment, document signing, approval workflows

State machines:
  Order statuses (pending → paid → shipped → delivered)
  Account statuses (unverified → active → suspended)
  Ticket statuses (open → in-review → resolved → closed)
  Subscription states (trial → active → expired → cancelled)

Feature flags and contexts:
  Beta features, premium features, region-locked features,
  role context switching (personal/business/admin)
```

---

## Tasks
- [ ] #task Map all multi-step workflows — test direct access to final step
- [ ] #task Identify all state machines — test invalid state transitions
- [ ] #task Check if prices/amounts/quantities are validated server-side
- [ ] #task Identify all "one per account" endpoints → test with [[Race-Condition-BAC]] technique
- [ ] #task Test Referer-based access control (spoof header)
- [ ] #task Test invite/share links for identity binding weakness

---

## 🔗 Related Notes
- [[Race-Condition-BAC]] — dedicated race condition exploitation guide
- [[Testing-Checklist]]
- [[Horizontal-vs-Vertical]]
- [[Parameter-Tampering]]

---
*Tags: #business-logic #bac #logic-flaw #theory*
