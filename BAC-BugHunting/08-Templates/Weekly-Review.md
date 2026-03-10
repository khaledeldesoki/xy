---
tags: [bac, template, weekly-review, periodic]
type: template
date: <% tp.date.now("YYYY-MM-DD") %>
week: <% tp.date.now("YYYY-[W]WW") %>
---

# 📅 Weekly Hunt Review — <% tp.date.now("YYYY-[W]WW") %>

> Fill this out every Sunday. 20 minutes reviewing = 2× improvement speed.

---

## 🎯 This Week's Programs

| Program | Hours Spent | Findings | Submitted | Outcome |
|---|---|---|---|---|
| | | | | |
| | | | | |

---

## 🐛 Bugs Found This Week

```dataview
TABLE
  program AS "Program",
  type AS "Type",
  severity AS "Severity",
  status AS "Status",
  payout AS "Payout"
FROM "BAC-BugHunting"
WHERE date_found >= date(this.file.day) - dur(7 days)
SORT date_found DESC
```

---

## ✅ What Worked This Week

> Techniques, approaches, or tools that actually found bugs or led to good recon.

-
-
-

---

## ❌ What Didn't Work

> Time sinks, dead ends, techniques that yielded nothing on this type of target.

-
-
-

---

## 🧠 New Techniques Learned

> From write-ups, Discord, conference talks, or your own experiments.

-
-
-

---

## 📊 Hunting Metrics

| Metric | This Week | All Time |
|---|---|---|
| Programs tested | | |
| Hours hunted | | |
| Bugs found | | |
| Bugs submitted | | |
| Bugs accepted | | |
| Duplicates | | |
| Earnings | | |

---

## 🎯 Focus for Next Week

### Top 3 Priorities
1. 
2. 
3. 

### Techniques to Practice
- [ ] 
- [ ] 
- [ ] 

### Labs to Complete
- [ ] 
- [ ] 

---

## 💡 Patterns Noticed

> Any emerging patterns — what endpoints are most often vulnerable, what programs pay well for BAC, what techniques consistently work?

-

---

## 📚 Reading / Study Queue

- [ ] Write-up: 
- [ ] Lab: 
- [ ] CVE: 

---

## 🔗 Related
- [[Findings-Database]] | [[Hunting-Board]] | [[Why-Reports-Fail]]

---
*Tags: #weekly-review #periodic #bac*
