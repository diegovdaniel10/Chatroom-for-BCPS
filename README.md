# BCPS Student Chatroom (local demo)

A Discord-inspired chat platform for BCPS students. Python standard-library backend (REST + WebSockets + SQLite),
plain HTML/CSS/JavaScript frontend. **Local demo only** - demo sign-in does not verify identity and must not be used
with real student accounts until BCPS approval, privacy review and security review are complete.

## Windows quick start
1. Install Python 3.10+ from python.org (tick **Add python.exe to PATH**). No `pip install` is needed.
2. Double-click `run.bat` (creates `.env` from `.env.example` on first run).
3. Open http://127.0.0.1:3000.
4. The console prints a **single-use Owner claim code** when the database is empty. On the sign-in screen choose
   "I have an owner claim code", enter a display name plus the code, and you become Owner of every seeded server.
   Everyone else signs in with just a display name and starts as a Student. The console also prints the
   one-time invite code for the invite-only "Staff Room".
5. Run the tests with `run_tests.bat` (or `python -m unittest discover -s tests -v`).

macOS/Linux: `python3 backend/server.py`.

## Database
SQLite file at `data/chat.db`, created and seeded automatically (3 servers, example channels). To reset, stop the
server and delete the `data` folder. All SQL is in `backend/db.py` and `backend/server.py` using portable SQL; moving
to PostgreSQL means writing a `Database` adapter (not done yet, see COMPLETION_REPORT.md).

## Layout
- `backend/server.py` - HTTP API, WebSocket hub, static file serving, startup
- `backend/permissions.py` - the nine roles, colors, badges, permission sets, hierarchy rules
- `backend/security.py` - signed session cookies, name/message validation
- `backend/db.py` - schema, SQLite layer, seed data
- `public/` - `index.html`, `styles.css`, `app.js`
- `tests/` - 29 unit/integration tests (`test_app.py`) and an optional browser test (`e2e_browser.py`, needs Playwright)

## Configuration (.env)
See `.env.example`. In production (`APP_ENV=production`) the server refuses to start with `DEMO_MODE=true` or a
`SESSION_SECRET` shorter than 32 characters, and cookies get the `Secure` flag (serve over HTTPS).

## Roles (lowest to highest)
Student, Normie, Helper, Moderator, Admin, Developer, Super Admin, Co-Owner, Owner. See COMPLETION_REPORT.md for the
exact permission table.

## Publishing to GitHub
```
git init
git add .
git commit -m "BCPS chatroom: roles, servers, channels, real-time messaging, moderation"
git branch -M main
git remote add origin https://github.com/diegovdaniel10/Chatroom-for-BCPS.git
git push -u origin main
```
(If the repo already has commits: `git pull origin main --allow-unrelated-histories` first.) `.gitignore` keeps `.env`
and the `data/` folder (database, dev secret) out of the repository.
