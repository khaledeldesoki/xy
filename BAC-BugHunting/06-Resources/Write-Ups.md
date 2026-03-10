---
tags: [bac, resources, writeups, hackerone, bugbounty]
type: resources
date: 2026-03-10
---

# 📖 BAC Write-Ups — Learn From the Best

## Must-Read IDOR Write-Ups

### 1. Stealing Your Private YouTube Videos, One Frame at a Time
```
Researcher: Brett Buerhaus
Platform: Google / YouTube
Bug: IDOR in YouTube's private video frame extraction API
Impact: Extract any frame from any private video
Technique: Discovered endpoint via JavaScript analysis, 
           changed video ID to private video IDs
Takeaway: Check ALL media/asset endpoints, not just data APIs
Link: https://buer.haus/2020/09/24/stealing-your-private-youtube-videos/
```

### 2. How I Found 12 Vulnerabilities in Instagram in 10 Minutes
```
Researcher: Laxman Muthiyah
Platform: Facebook/Instagram
Bug: Multiple IDOR and access control issues
Technique: Systematic API enumeration and ID substitution
Takeaway: Thorough enumeration beats creative testing for IDOR
```

### 3. GitLab Private Repository Access via IDOR
```
Platform: GitLab
CVE: N/A (bug bounty)
Bug: IDOR on repository import functionality
Impact: Read contents of private repositories
Technique: Import endpoint accepted target repo ID without auth check
Takeaway: Import/export features often have weaker auth than main CRUD
```

### 4. HackerOne's Own IDOR Bug
```
Researcher: #hackeronehq was affected
Bug: IDOR in report access via team token  
Impact: Access private vulnerability reports
Technique: Token from one team accepted on another team's reports
Takeaway: Even security companies have IDOR bugs
```

---

## Must-Read Privilege Escalation Write-Ups

### 5. Gaining Admin Access via Mass Assignment (Trello)
```
Platform: Trello
Bug: Mass assignment on board update — could set isAdmin: true
Impact: Any user becomes board admin
Technique: Observed admin field in response, included in PUT request
Takeaway: Always look at response fields, try sending them back
```

### 6. Bypassing Admin Authentication via X-Original-URL
```
Platform: Internal corporate app
Bug: Nginx proxied /admin to upstream, 
     upstream trusted X-Original-URL header
Impact: Any user accesses admin panel with X-Original-URL: /admin
Takeaway: Header-based bypasses work on apps behind proxies
```

---

## GraphQL BAC Write-Ups

### 7. Breaking GraphQL Authorization
```
Researcher: Various
Pattern: GraphQL introspection → find admin mutations →
         execute without admin role
Technique: introspection → find deleteUser mutation →
           call as regular user
Takeaway: Always run introspection, test every mutation for BFLA
```

---

## How to Find More Write-Ups

```bash
# HackerOne disclosed reports
https://hackerone.com/hacktivity?filter=type:disclosed
# Filter: "Access Control" category

# Google dorking
site:hackerone.com/reports "idor"
site:hackerone.com/reports "broken access control"
site:medium.com "idor" "bug bounty" 2024
site:infosec.medium.com "access control bypass"

# GitHub
https://github.com/reddelexc/hackerone-reports
https://github.com/ngalongc/bug-bounty-reference

# Specific query
inurl:hackerone.com/reports idor disclosed
```

---

## 🔗 Related Notes
- [[CVEs-BAC]]
- [[Labs-Practice]]
- [[Reporting-BAC]]

---
*Tags: #writeups #bac #resources #hackerone*
