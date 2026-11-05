# Completion Report

Tested: Python 3.12 on Linux - 29 automated tests pass (`./run_tests.sh`), plus a headless Chromium run (the same
engine as Chrome on ChromeOS): login, real-time delivery between two browsers, live role change, XSS text rendered inert,
phone-width layout. **Not tested on a physical Chromebook** (no device available); the client is plain HTML/CSS/JS with
no installs, and message tools are always visible on touch screens. Please open it once on a school Chromebook.

## Completed features
- **Nine roles in the exact order**, each with its own color and badge: Student, Normie, Helper, Moderator, Admin,
  Developer, Super Admin, Co-Owner, Owner. Roles are stored per server membership and checked on the server for every request.
- **Servers and channels**: server rail with icons, switching, join open servers, invite-code servers (codes stored hashed),
  channel list per role, channel-level read/post restrictions, create/delete channels. Seeded: BCPS Hub (#general,
  #announcements, #homework-help, #school-talk, #gaming, #clubs, #questions, plus #staff-lounge for Helpers+),
  Clubs Corner, and the invite-only Staff Room. Text channels only; the `kind` column leaves room for voice later.
- **Messaging**: real-time delivery over WebSockets, timestamps, role-colored names with badges, history (last 50, paged by `before`),
  edit own, delete (own, or others by hierarchy), reactions (6 emoji), reporting, unread markers.
- **Moderation**: timeouts (10 min to 28 days, blocks posting/reacting/editing), report queue with resolve/dismiss,
  delete from a report, audit log, diagnostics page.
- **Member list** with online status, grouped by role, profile panel with bio, role management and timeout controls.
- **Responsive** desktop and mobile layout with slide-out panels; polling fallback if the WebSocket drops.
- **Security**: HMAC-signed HttpOnly SameSite=Strict session cookies (Secure in production); roles re-read from the database
  on every request; Origin check on every state-changing request and WebSocket upgrade; strict CSP (no inline scripts/styles),
  nosniff, frame denial; all user text rendered with `textContent`; input validation (names, messages, topics, bios, channel names;
  control and bidi-override characters rejected); reserved staff-style display names blocked; request body cap; per-IP, per-user
  and per-role rate limits plus duplicate-message blocking; hidden channels return 404; path-traversal protection on static files;
  no password handling at all.
- **Privacy**: audit log stores actions and user IDs/names, never message content; deleted message text is blanked unless an open
  report still needs it; reporter identity is visible only to roles that can resolve reports; diagnostics return counts only.

## Permission table
| Role | Permissions |
|---|---|
| Student | read, send, react, report (6 msgs/10s) |
| Normie | same as Student (8 msgs/10s) |
| Helper | + view reports |
| Moderator | + resolve reports, delete messages (lower roles), timeout members (lower roles); post in #announcements |
| Admin | + manage channels, server name/description, assign roles below Admin |
| Developer | read/send/react/report + diagnostics only; no moderation, no role management |
| Super Admin | Admin + audit log + diagnostics; can assign roles up to Developer |
| Co-Owner | Super Admin + invite codes; can assign roles up to Super Admin |
| Owner | Co-Owner + the only role that can appoint a Co-Owner; cannot be changed or assigned by anyone |

Rules: nobody can change their own role; you can only act on members strictly below you; Owner can never be assigned
(owner is claimed once via the console code). Roles are not inherited from level - each role has an explicit permission set.

## Not done / honest limitations
- **PostgreSQL**: not implemented. The data layer is isolated (`db.py`) and uses portable SQL, but a Postgres adapter still has to be written.
- **Voice channels**, **kick/ban**, **ownership transfer**, **DMs**, **file uploads**, **message search**: not built.
- **Normie vs Student**: identical permissions; only a slightly higher message rate. Tell me if you want a real difference.
- **Authentication is demo-only** (display name). Demo names are unique and cannot be reclaimed after the cookie expires (8 hours).
- The WebSocket server is a small hand-written stdlib implementation (one thread per connection) - fine for a demo/class-sized use, not for thousands of users. Production should sit behind HTTPS/a reverse proxy.
- No automated content filtering (profanity/PII detection); moderation is report-based.

## Still requires BCPS approval or external integration
- BCPS approval of the project, privacy review (student data, COPPA/FERPA-style requirements) and security review before any real student onboarding.
- A district-approved identity provider (SSO/SAML/OIDC) replacing demo sign-in, mapped to roles by the district.
- Hosting the server (Chromebooks only run the browser client), a school-network/web-filter allowance for the server address and WebSocket (`wss://`) connections, HTTPS certificates, backups, data-retention policy and incident process; a PostgreSQL deployment if required.
- A staffed moderation process and escalation path for threats/self-harm reports.
- Accessibility review and an independent penetration test.
