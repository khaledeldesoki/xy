---
tags: [bac, findings, database, tracker, index]
type: tracker
date: 2026-03-10
---

# 🗄 Findings Database — Index & Stats

> **Architecture**: Each finding is a separate `.md` file inside `06-Resources/findings/`. This makes every finding individually queryable by Dataview. Use the template below to create a new finding file.

---

## ➕ Creating a New Finding

1. Create a new file: `06-Resources/findings/YYYY-MM-DD-NNN-short-title.md`
2. Paste the frontmatter template below and fill it in
3. It will automatically appear in all Dataview tables on this page

### Finding File Frontmatter Template

```yaml
---
tags: [finding, bac]
type: finding
program: Target Corp (HackerOne)
platform: HackerOne
bug_type: IDOR
endpoint: /api/v1/orders/{id}
severity: High
status: Submitted
cvss: 8.1
payout: 0
date_found: 2026-03-10
date_submitted: 2026-03-10
impact: "Attacker can read any user's full order history including billing address and last-4 card digits"
report_url: ""
duplicate: false
notes: "Sequential integer IDs, no ownership check server-side"
---

# Finding: [TITLE]

## Request
\`\`\`http
GET /api/v1/orders/VICTIM_ID HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
\`\`\`

## Response
\`\`\`json
{
  "order_id": 7845,
  "user_email": "victim@example.com",
  "items": [...],
  "billing": {...}
}
\`\`\`

## Impact
[Describe real-world impact here]

## Chain Potential
[Any chaining opportunities?]
```

---

## 📊 All Findings

```dataview
TABLE
  program AS "Program",
  bug_type AS "Type",
  severity AS "Severity",
  status AS "Status",
  ("$" + string(payout)) AS "Payout",
  date_found AS "Found"
FROM "BAC-BugHunting/06-Resources/findings"
WHERE type = "finding"
SORT date_found DESC
```

---

## 💰 Earnings & Stats

```dataview
TABLE WITHOUT ID
  length(rows) AS "Total Findings",
  length(filter(rows, (r) => r.status = "Accepted")) AS "✅ Accepted",
  length(filter(rows, (r) => r.duplicate = true)) AS "🔁 Dupes",
  length(filter(rows, (r) => r.status = "Submitted" OR r.status = "Triaged")) AS "⏳ Pending"
FROM "BAC-BugHunting/06-Resources/findings"
WHERE type = "finding"
GROUP BY "Overview"
```

---

## 📈 By Severity

```dataview
TABLE WITHOUT ID
  severity AS "Severity",
  length(rows) AS "Count"
FROM "BAC-BugHunting/06-Resources/findings"
WHERE type = "finding"
GROUP BY severity
SORT rows.severity ASC
```

---

## 🐛 By Bug Type

```dataview
TABLE WITHOUT ID
  bug_type AS "Type",
  length(rows) AS "Count"
FROM "BAC-BugHunting/06-Resources/findings"
WHERE type = "finding"
GROUP BY bug_type
SORT length(rows) DESC
```

---

## ⏳ Pending / In-Flight

```dataview
TABLE
  program AS "Program",
  bug_type AS "Type",
  severity AS "Severity",
  status AS "Status",
  date_submitted AS "Submitted"
FROM "BAC-BugHunting/06-Resources/findings"
WHERE type = "finding"
AND (status = "Drafting" OR status = "Submitted" OR status = "Triaged")
SORT date_submitted ASC
```

---

## 🏆 Top Payouts

```dataview
TABLE
  program AS "Program",
  bug_type AS "Type",
  severity AS "Severity",
  ("$" + string(payout)) AS "Payout"
FROM "BAC-BugHunting/06-Resources/findings"
WHERE type = "finding" AND payout > 0
SORT payout DESC
LIMIT 10
```

---

## 🔗 Related
- [[Bug-Report-Template]] | [[Reporting-BAC]] | [[Why-Reports-Fail]]

---
*Tags: #findings #database #tracker*
