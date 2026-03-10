---
tags: [bac, resources, defensive, rbac, abac, architecture]
type: resources
date: 2026-03-10
---

# 🛡 Defensive Knowledge — How BAC Is Supposed to Work

> **Why study defense as a hunter?** When you understand exactly how RBAC/ABAC/Zanzibar works — and where each model fails — you can find the gaps systematically, not by luck.

---

## The Three Access Control Models

### 1. RBAC — Role-Based Access Control

```
Principle: Users have roles. Roles have permissions. 
           Access = role check.

User → [has role] → Role → [has permission] → Resource

Example:
  Alice has role: "editor"
  Role "editor" has permission: "write:articles"
  Alice requests POST /articles → check: editor.write:articles → allow

WHERE IT BREAKS:
  ✗ Roles assigned at registration from user-supplied input (mass assign)
  ✗ Role check done client-side only (hidden button, JS check)
  ✗ Role check done on HTTP method but not all methods (verb tampering)
  ✗ Role hierarchy implemented incorrectly (user can escalate to moderator)
  ✗ JWT role claim not re-validated server-side on each request
  ✗ Separate role table not joined on every query (stale role cache)
```

**Hunter implication**: With RBAC, try every admin/moderator endpoint from a "user" role. The check is often a simple `if user.role == "admin"` that can be bypassed by manipulating the role field.

---

### 2. ABAC — Attribute-Based Access Control

```
Principle: Access decisions based on attributes of subject, object, 
           environment, and action. More granular than RBAC.

Policy: subject.department == object.owner_department 
        AND action == "read"
        AND time.now < 18:00

WHERE IT BREAKS:
  ✗ Attributes sourced from user-controlled input (request body, JWT claims)
  ✗ "Owner" attribute is the user-supplied object ID (classic IDOR)
  ✗ Policy engine missing cases (default-allow, not default-deny)
  ✗ Environment attributes (IP, time) checked only in one place
  ✗ Attribute cache staleness — policy evaluated on old state
  ✗ Complex policies with logic bugs (A AND B OR C != A AND (B OR C))
```

**Hunter implication**: With ABAC, look for attributes injected via mass assignment (`owner_department: "finance"`) or environment overrides (`X-Forwarded-For: 10.0.0.1` for "internal" attribute).

---

### 3. ReBAC / Zanzibar — Relationship-Based Access Control

```
Principle: Access based on graph of relationships between entities.
           "Alice can edit Document X because Alice is a member of 
            Team Y which owns Project Z which contains Document X."

Used by: Google (Zanzibar), GitHub, Airbnb, Notion, Linear

WHERE IT BREAKS:
  ✗ Relationship graph traversal not bounded (unbounded graph walk)
  ✗ Relationship creation not properly authorized (anyone can add edges)
  ✗ Cached permission graph stale (update revoked access, cache says allowed)
  ✗ Wildcard relationships ("member of *" matches all objects)
  ✗ Cross-tenant relationship traversal (org A member walks into org B)
```

**Hunter implication**: In SaaS apps, try adding yourself to a group/team you shouldn't access. If the relationship API doesn't verify you can add to that specific entity, you may walk into other tenants' data.

---

## Common Implementation Patterns & Their Flaws

### Pattern: Check on Route, Not on Data Layer

```javascript
// ✗ WRONG: auth check at route level only
app.get('/admin/users', requireAdmin, (req, res) => {
    // requireAdmin passes → but what if user calls /admin/../users ?
    // What if another route calls this handler without the middleware?
    const users = db.getAllUsers();
    res.json(users);
});

// ✓ CORRECT: check at data layer too
async function getAllUsers(requestingUser) {
    if (requestingUser.role !== 'admin') throw new ForbiddenError();
    return db.getAllUsers();
}
```

**What you can exploit**: Path normalization bypass, route ordering issues, middleware skip via alternative HTTP method.

---

### Pattern: Ownership Not Enforced in Query

```javascript
// ✗ WRONG: trusts user-supplied ID, fetches any record
app.get('/api/orders/:id', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.id); // ← IDOR!
    res.json(order);
});

// ✓ CORRECT: scopes query to authenticated user
app.get('/api/orders/:id', authenticate, async (req, res) => {
    const order = await Order.findOne({
        _id: req.params.id,
        userId: req.user.id  // ← ownership enforced in query
    });
    if (!order) return res.status(403).json({error: "Forbidden"});
    res.json(order);
});
```

**What you can exploit**: The first pattern is a direct IDOR. Look for `findById`, `getById`, `db.query("SELECT * FROM orders WHERE id = ?", id)` patterns in open-source code.

---

### Pattern: Client-Side Access Control

```javascript
// ✗ WRONG: admin menu hidden via CSS/JS
if (user.role !== 'admin') {
    document.getElementById('adminButton').style.display = 'none';
}
// The endpoint /api/admin still works — browser just doesn't show the button!

// ✗ WRONG: React route guard
const AdminRoute = ({component: Component}) => (
    <Route render={props =>
        user.isAdmin ? <Component {...props}/> : <Redirect to="/home"/>
    }/>
);
// The API endpoints /api/admin/* are still fully accessible!
```

**What you can exploit**: Any hidden UI element. Right-click → Inspect → find hidden buttons/links. Directly call the API endpoints the admin UI uses.

---

### Pattern: Missing Authorization on Async/Background Jobs

```
Common oversight:
  POST /api/report/generate {"report_id": "MY_ID"}  → 200 (authorized)
  GET /api/report/status/{job_id}                   → 200 (no auth check!)
  GET /api/report/download/{job_id}                 → 200 (no auth check!)

Because the auth was done at job creation time,
dev assumes all subsequent steps are authorized.

→ IDOR the job_id to access other users' reports/exports
→ Often exposes bulk data exports, financial reports, user data CSVs
```

---

## Defense Bypass Mental Model

```
When you see a protected endpoint, ask:
  1. Where is the check done? Route middleware, controller, data layer?
     → Try bypasses at each layer
  
  2. What is the check based on? Session, JWT, cookie, header?
     → Tamper the token carrying the identity
  
  3. Is ownership checked, or just authentication?
     → IDOR test: can I access other users' objects?
  
  4. Is the check on the object itself, or just access to the endpoint?
     → Nested resource IDOR, indirect reference attacks
  
  5. What happens when the check fails? 403, redirect, or silent ignore?
     → 302 redirect may still render data before redirecting
     → 403 body may contain partial data
  
  6. Are there multiple paths to the same resource?
     → REST + GraphQL both accessing same data
     → Internal service endpoint + public endpoint
     → v1 API + v2 API pointing to same backend
```

---

## 🔗 Related Notes
- [[BAC-Overview]]
- [[IDOR]]
- [[Horizontal-vs-Vertical]]
- [[Advanced-BAC-Chains]]

---
*Tags: #defensive #rbac #abac #bac #resources*
