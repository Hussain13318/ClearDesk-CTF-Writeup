# ClearDesk  CTF Write-up

**Lab:** [ClearDesk](https://hackerdna.com/labs/cleardesk)
**Platform:** HackerDNA
**Difficulty:** Medium
**Category:** Web & API Security
**Date:** November 1, 2026
**Flags:** 2 (User + Root)

*This was done against an authorized HackerDNA lab instance, not a real production system.*

## First impressions

ClearDesk looked like a pretty standard internal helpdesk tool  login page, demo creds provided on the page itself, nothing flashy. Once I logged in I landed on a dashboard for "Alex Kim," an IT Support intern, with two support tickets sitting there. There was also a "View Profile (API)" link on the dashboard, which honestly is what got me curious first. Anytime an app shows me it's calling an API directly like that, I want to see what that API actually returns.

## Finding the IDOR

Clicking that link took me to `/api/user/3`, which returned Alex Kim's profile as raw JSON:

```json
{"department":"IT Support","email":"a.kim@hdna.me","id":3,"name":"Alex Kim","role":"Intern"}
```

Obvious next move  change the number. I tried `/api/user/1`:

```json
{"department":"IT Administration","email":"s.chen@hdna.me","id":1,"name":"Sarah Chen","role":"IT Director"}
```

No auth check at all. I was logged in as the intern and it just handed me the IT Director's full profile. Tried `/api/user/2` and `/api/user/4` too and got Mike Roberts (Senior Developer) and Jordan Lee (UI Designer) back, no problem. Tried `0` and `5` just to map the range and both came back `{"error":"User not found"}`, so I knew the valid range was 1–4.

Classic IDOR. The endpoint trusts whatever ID you give it instead of checking if the logged-in user actually owns that record.

## Same bug, different endpoint

Since the dashboard also showed tickets, I figured the ticket API probably had the exact same problem. Alex Kim only "owned" tickets #2 and #3 on the dashboard, but I just started hitting `/api/ticket/{id}` directly from 1 through 8.

Ticket #1 is where things got interesting:

```json
{"created":"2026-03-08T09:15:00Z","description":"Annual security audit findings  CONFIDENTIAL.\n\nFLAG: [flag redacted]","id":1,"owner_id":1,"priority":"critical","status":"open","subject":"Confidential: Annual Security Audit"}
```

That's the user flag, just sitting in a ticket owned by Sarah Chen that I had no business reading.

I kept going through the rest of the tickets anyway because I wanted to see how far this went  #2 and #3 were Alex's own (wifi issue, monitor request), #4 and #5 belonged to Mike Roberts (VPN problems, staging access request), #6 and #7 belonged to Jordan Lee (Figma license, monitor calibration). Ticket #9 came back not found, so 8 total tickets existed.

Ticket #8 is where it got really bad:

```json
{"created":"2026-03-09T16:45:00Z","description":"Temporary admin password has been reset per policy. New credentials: [redacted]. Please change after first login.\n\nAlso: the nightly backup job is failing to read /root/flag-root.txt (permission denied). Please check file permissions after login.  IT Security Team","id":8,"owner_id":1,"priority":"high","status":"resolved","subject":"Password Reset: Admin Portal Access"}
```

Plaintext admin credentials sitting in a support ticket. And as a bonus, it literally told me the root flag's filename and path. I didn't even have to go looking for it.

## Logging in as admin

Signed out, logged back in with the leaked admin credentials from that ticket. Completely different dashboard this time  Sarah Chen's profile, her two tickets, and a whole "Admin Panel" section I hadn't seen before: a Log Viewer (`app.log`, `error.log`, `access.log`) and a User Management link.

The Log Viewer links looked like this:

```
/admin/logs?file=app.log
/admin/logs?file=error.log
/admin/logs?file=access.log
```

That `file=` parameter is basically begging to be abused. Server-side it's almost certainly just reading whatever file path you give it with no validation  and since the earlier ticket literally told me the flag lived at `/root/flag-root.txt`, I didn't even need to mess with path traversal payloads. I just tried the absolute path straight up:

```
/admin/logs?file=/root/flag-root.txt
```

```
[flag redacted]
```

That was it. Root flag, no traversal tricks needed, because the app trusted the full path I gave it.

## Vulnerability Breakdown

| Vuln | Root Cause | Impact | Fix |
|---|---|---|---|
| **IDOR** on `/api/user/{id}` and `/api/ticket/{id}` | No server-side check that the requested resource belongs to the authenticated session | Any logged-in user (even the lowest-privilege intern account) could read every other employee's profile and every support ticket, regardless of ownership | Enforce object-level authorization on every request  check `ticket.owner_id == session.user_id` (or an explicit role check) before returning data |
| **Sensitive data stored in plaintext** inside ticket descriptions | Admin password was reset and the new credentials were pasted directly into a support ticket body instead of a secure channel | Leaked a working admin account, which became the actual path to root | Never put credentials in ticket systems, chat logs, or any place not specifically designed for secret storage; use a password manager / vault with audit logging |
| **Arbitrary File Read (LFI)** in the admin Log Viewer | `file` query parameter passed directly into a file-read function with no allowlist or path sanitization | Authenticated admin could read any file on the server filesystem, including files well outside the intended logs directory | Only allow reading from a fixed, whitelisted set of filenames inside a specific directory; reject any input containing `/`, `..`, or absolute paths |

## Lessons Learned

- I almost didn't check the "View Profile (API)" link at all  just assumed it was a formality. Turned out to be the entry point for the whole chain. Always poke at anything that visibly calls an API.
- Enumerating ticket IDs felt tedious at first (I was literally just incrementing numbers), but it paid off fast. Sometimes brute-force curiosity beats cleverness.
- The part that actually surprised me was that I didn't need any traversal payload for the LFI  the app just trusted an absolute path outright. I went in expecting to fight a filter and there wasn't one.
- Finding credentials inside a "support ticket" instead of some config file was a good reminder that secrets leak in weird, mundane places, not just `.env` files.

## Attack Chain Summary

```
IDOR on /api/user/{id} and /api/ticket/{id}
   → read Sarah Chen's confidential ticket (USER FLAG)
   → read ticket #8, leaked admin credentials + flag file path
   → logged in as admin
   → admin panel exposes Log Viewer with unsanitized `file` param
   → requested /admin/logs?file=/root/flag-root.txt directly
   → ROOT FLAG
```

Lab: [https://hackerdna.com/labs/cleardesk](https://hackerdna.com/labs/cleardesk)
