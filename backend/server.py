"""BCPS student chatroom server (Python standard library only).

REST API + a small RFC 6455 WebSocket implementation for real-time events, SQLite storage,
role-based permissions enforced on the server for every action.

LOCAL DEMO ONLY: demo sign-in does not verify student identity. A district-approved identity
provider and BCPS privacy/security review are required before real student accounts are used.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import struct
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs, unquote, urlsplit

import permissions as P
from db import Database, hash_code, seed
from security import (SESSION_COOKIE, SESSION_TTL_SECONDS, clean_text, normalize_display_name,
                      read_cookie, sign_session, validate_message, verify_session)

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DIR = (ROOT / "public").resolve()
MAX_HTTP_BODY = 8 * 1024
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
REACTIONS = ["👍", "❤️", "😂", "🎉", "😮", "😢"]
REPORT_REASONS = {"bullying", "personal-information", "threat", "spam", "other"}
UUID_RE = r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"


class ApiError(Exception):
    def __init__(self, status: int, message: str, headers: dict | None = None) -> None:
        super().__init__(message)
        self.status, self.message, self.headers = status, message, headers


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


# --------------------------------------------------------------------------- WebSockets
def ws_frame(opcode: int, payload: bytes) -> bytes:
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


class WSConn:
    def __init__(self, handler: "Handler", user_id: str) -> None:
        self.handler, self.user_id, self.lock, self.alive = handler, user_id, Lock(), True

    def send_raw(self, frame: bytes) -> None:
        with self.lock:
            try:
                self.handler.wfile.write(frame)
                self.handler.wfile.flush()
            except OSError:
                self.alive = False

    def send(self, event: dict) -> None:
        self.send_raw(ws_frame(0x1, json.dumps(event, ensure_ascii=False).encode("utf-8")))


class Hub:
    def __init__(self, app: "App") -> None:
        self.app, self.conns, self.lock = app, set(), Lock()

    def add(self, conn: WSConn) -> None:
        with self.lock:
            self.conns.add(conn)

    def remove(self, conn: WSConn) -> None:
        with self.lock:
            self.conns.discard(conn)

    def count_for(self, user_id: str) -> int:
        with self.lock:
            return sum(1 for c in self.conns if c.user_id == user_id and c.alive)

    def online(self, user_id: str) -> bool:
        return self.count_for(user_id) > 0

    def total(self) -> int:
        with self.lock:
            return len(self.conns)

    def broadcast(self, event: dict, server_id: str, channel_id: str | None = None) -> None:
        """Send to members of the server; for channel events only to members who may read it."""
        min_read = 1
        if channel_id:
            ch = self.app.db.one("SELECT min_read FROM channels WHERE id=?", (channel_id,))
            if not ch:
                return
            min_read = ch["min_read"]
        with self.lock:
            conns = list(self.conns)
        for conn in conns:
            if not conn.alive:
                continue
            m = self.app.membership(server_id, conn.user_id)
            if m and P.level(m["role"]) >= min_read:
                conn.send(event)

    def presence(self, user_id: str) -> None:
        for row in self.app.db.q("SELECT server_id FROM memberships WHERE user_id=?", (user_id,)):
            self.broadcast({"type": "presence", "serverId": row["server_id"], "userId": user_id}, row["server_id"])


# --------------------------------------------------------------------------- Application state
class App:
    def __init__(self, db_path: str, secret: str, demo_mode: bool = True, production: bool = False,
                 allowed_origins: set[str] | None = None, owner_code: str | None = None) -> None:
        if production and demo_mode:
            raise RuntimeError("DEMO_MODE must be false in production.")
        if production and len(secret) < 32:
            raise RuntimeError("Production requires SESSION_SECRET with at least 32 characters.")
        self.db = Database(db_path)
        self.seed_codes = seed(self.db)
        self.secret, self.demo_mode, self.production = secret, demo_mode, production
        self.allowed_origins = allowed_origins or set()
        self.hub = Hub(self)
        self.started = time.time()
        self.login_limit = 30  # sign-ins per minute per IP
        self._windows: dict[str, tuple[float, int]] = {}
        self._msg_windows: dict[str, deque] = {}
        self._last_msg: dict[str, tuple[str, float]] = {}
        self._lock = Lock()
        has_owner = self.db.one("SELECT 1 FROM memberships WHERE role='owner'")
        self.owner_code = None if (has_owner or not demo_mode) else (owner_code or secrets.token_urlsafe(9))

    # --- helpers
    def rate_allowed(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._windows) > 20000:
                self._windows = {k: v for k, v in self._windows.items() if now - v[0] < 120}
            started, count = self._windows.get(key, (now, 0))
            if now - started >= window:
                started, count = now, 0
            self._windows[key] = (started, count + 1)
            return count + 1 <= limit

    def message_rate_allowed(self, user_id: str, role: str, text: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            last = self._last_msg.get(user_id)
            if last and last[0] == text and now - last[1] < 8:
                return "Please don't repeat the same message."
            stamps = self._msg_windows.setdefault(user_id, deque())
            while stamps and now - stamps[0] >= 10:
                stamps.popleft()
            if len(stamps) >= P.MESSAGE_RATE.get(role, 6):
                return "Slow down and try again in a moment."
            stamps.append(now)
            self._last_msg[user_id] = (text, now)
        return None

    def membership(self, server_id: str, user_id: str) -> dict | None:
        return self.db.one("SELECT * FROM memberships WHERE server_id=? AND user_id=?", (server_id, user_id))

    def audit(self, server_id: str, actor_id: str, action: str, target_id: str | None = None, detail: str = "") -> None:
        self.db.x("INSERT INTO audit_log(server_id,actor_id,action,target_id,detail,created_at) VALUES(?,?,?,?,?,?)",
                  (server_id, actor_id, action, target_id, detail, int(time.time() * 1000)))

    def origin_ok(self, origin: str | None, host: str) -> bool:
        if not origin:
            return False
        norm = origin.rstrip("/")
        if self.allowed_origins:
            return norm in self.allowed_origins
        return norm in {f"http://{host}", f"https://{host}"}

    def user_from_cookie(self, cookie_header: str | None) -> dict | None:
        session = verify_session(read_cookie(cookie_header), self.secret)
        if not session:
            return None
        return self.db.one("SELECT id,name,bio FROM users WHERE id=?", (session["id"],))

    # --- message serialization
    MSG_SQL = ("SELECT m.seq, m.id, m.channel_id, m.user_id, m.text, m.created_at, m.edited_at, "
               "u.name AS author_name, COALESCE(ms.role,'student') AS author_role "
               "FROM messages m JOIN users u ON u.id=m.user_id JOIN channels c ON c.id=m.channel_id "
               "LEFT JOIN memberships ms ON ms.server_id=c.server_id AND ms.user_id=m.user_id ")

    def messages_out(self, rows: list[dict]) -> list[dict]:
        reacts: dict[str, dict[str, list[str]]] = {}
        if rows:
            marks = ",".join("?" * len(rows))
            for r in self.db.q(f"SELECT message_id,emoji,user_id FROM reactions WHERE message_id IN ({marks}) ORDER BY rowid",
                               tuple(r["id"] for r in rows)):
                reacts.setdefault(r["message_id"], {}).setdefault(r["emoji"], []).append(r["user_id"])
        return [{"id": r["id"], "seq": r["seq"], "channelId": r["channel_id"],
                 "user": {"id": r["user_id"], "name": r["author_name"], "role": r["author_role"]},
                 "text": r["text"], "createdAt": r["created_at"], "editedAt": r["edited_at"],
                 "reactions": [{"emoji": e, "userIds": ids} for e, ids in reacts.get(r["id"], {}).items()]}
                for r in rows]

    def message_out(self, message_id: str) -> dict | None:
        out = self.messages_out(self.db.q(self.MSG_SQL + "WHERE m.id=?", (message_id,)))
        return out[0] if out else None


class Req:
    def __init__(self, app: App, method: str, user: dict | None, body: dict, query: dict, args: tuple,
                 peer: str, headers) -> None:
        self.app, self.method, self.user, self.body = app, method, user, body
        self.query, self.args, self.peer, self.headers = query, args, peer, headers


# --------------------------------------------------------------------------- Shared checks
def need_member(req: Req, server_id: str) -> dict:
    m = req.app.membership(server_id, req.user["id"])
    if not m:
        raise ApiError(404, "Server not found.")  # 404 so non-members can't probe for servers
    return m


def need_perm(m: dict, perm: str, message: str = "You don't have permission to do that.") -> None:
    if not P.has_perm(m["role"], perm):
        raise ApiError(403, message)


def need_channel(req: Req, channel_id: str) -> tuple[dict, dict]:
    ch = req.app.db.one("SELECT * FROM channels WHERE id=?", (channel_id,))
    if not ch:
        raise ApiError(404, "Channel not found.")
    m = need_member(req, ch["server_id"])
    if not P.has_perm(m["role"], "read") or P.level(m["role"]) < ch["min_read"]:
        raise ApiError(404, "Channel not found.")  # hidden channels look non-existent
    return ch, m


def need_message(req: Req, message_id: str) -> tuple[dict, dict, dict]:
    row = req.app.db.one("SELECT * FROM messages WHERE id=? AND deleted=0", (message_id,))
    if not row:
        raise ApiError(404, "Message not found.")
    ch, m = need_channel(req, row["channel_id"])
    return row, ch, m


def not_timed_out(m: dict) -> None:
    left = m["timeout_until"] - time.time()
    if left > 0:
        raise ApiError(403, f"You are timed out for {int(left // 60) + 1} more minute(s).")


def role_key(value: object, default: str = "student") -> str:
    if value is None:
        return default
    if not isinstance(value, str) or value not in P.ROLE_LEVEL:
        raise ApiError(400, "Unknown role.")
    return value


def channel_out(ch: dict, role: str) -> dict:
    return {"id": ch["id"], "serverId": ch["server_id"], "name": ch["name"], "topic": ch["topic"],
            "kind": ch["kind"], "minRead": P.ROLES[ch["min_read"] - 1], "minPost": P.ROLES[ch["min_post"] - 1],
            "canPost": P.has_perm(role, "send") and P.level(role) >= ch["min_post"]}


# --------------------------------------------------------------------------- Handlers
def h_health(req):
    return 200, {"ok": True, "mode": "demo" if req.app.demo_mode else "school-auth-required"}, None


def h_meta(req):
    roles = [{"key": r, "level": P.level(r), **P.ROLE_INFO[r]} for r in P.ROLES]
    return 200, {"roles": roles, "reactions": REACTIONS, "reportReasons": sorted(REPORT_REASONS)}, None


def session_payload(app: App, user: dict) -> dict:
    return {"authenticated": True, "demoMode": app.demo_mode,
            "student": {"id": user["id"], "name": user["name"], "bio": user["bio"]}}


def h_session(req):
    user = req.app.user_from_cookie(req.headers.get("Cookie"))
    if not user:
        return 401, {"authenticated": False, "demoMode": req.app.demo_mode}, None
    return 200, session_payload(req.app, user), None


def session_cookie(app: App, token: str, max_age: int) -> str:
    cookie = f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"
    return cookie + ("; Secure" if app.production else "")


def h_demo_session(req):
    app = req.app
    if not app.demo_mode:
        raise ApiError(404, "Not found.")
    if not app.rate_allowed(f"login:{req.peer}", app.login_limit, 60):
        raise ApiError(429, "Too many sign-in attempts. Try again shortly.")
    name = normalize_display_name(req.body.get("name"))
    if not name:
        raise ApiError(400, "Use a 2–24 character display name (letters, numbers, spaces, hyphens or underscores). "
                            "Names that look like staff titles are not allowed.")
    code = req.body.get("ownerCode")
    claim = code not in (None, "")
    if claim and (not isinstance(code, str) or not app.rate_allowed(f"owner:{req.peer}", 5, 60)):
        raise ApiError(429, "Too many attempts. Try again shortly.")
    with app.db.tx():
        if claim:
            if not app.owner_code or not hmac.compare_digest(code.encode(), app.owner_code.encode()):
                raise ApiError(403, "Invalid owner claim code.")
        if app.db.one("SELECT 1 FROM users WHERE name_lower=?", (name.lower(),)):
            raise ApiError(409, "That display name is already taken in this demo. Pick another.")
        uid, now = str(uuid.uuid4()), int(time.time() * 1000)
        app.db.x("INSERT INTO users(id,name,name_lower,bio,created_at) VALUES(?,?,?,?,?)", (uid, name, name.lower(), "", now))
        for s in app.db.q("SELECT id,auto_join FROM servers"):
            if claim:
                app.db.x("INSERT INTO memberships(server_id,user_id,role,joined_at) VALUES(?,?,?,?)", (s["id"], uid, "owner", now))
            elif s["auto_join"]:
                app.db.x("INSERT INTO memberships(server_id,user_id,role,joined_at) VALUES(?,?,?,?)", (s["id"], uid, "student", now))
        if claim:
            app.owner_code = None  # single use
    token = sign_session({"id": uid, "createdAt": now, "expiresAt": time.time() + SESSION_TTL_SECONDS}, app.secret)
    user = {"id": uid, "name": name, "bio": ""}
    return 200, session_payload(app, user), {"Set-Cookie": session_cookie(app, token, SESSION_TTL_SECONDS)}


def h_logout(req):
    return 204, None, {"Set-Cookie": session_cookie(req.app, "", 0)}


def h_update_me(req):
    bio = clean_text(req.body.get("bio", ""), 0, 160) if req.body.get("bio", "") != "" else ""
    if bio is None:
        raise ApiError(400, "Bio must be 160 characters or fewer, with no control characters.")
    req.app.db.x("UPDATE users SET bio=? WHERE id=?", (bio, req.user["id"]))
    return 200, {"bio": bio}, None


def h_servers(req):
    app, uid = req.app, req.user["id"]
    servers = []
    for s in app.db.q("SELECT s.*, ms.role, ms.timeout_until FROM memberships ms JOIN servers s ON s.id=ms.server_id "
                      "WHERE ms.user_id=? ORDER BY s.created_at, s.name", (uid,)):
        lvl = P.level(s["role"])
        chans = app.db.q("SELECT * FROM channels WHERE server_id=? AND min_read<=? ORDER BY position, name", (s["id"], lvl))
        servers.append({"id": s["id"], "name": s["name"], "description": s["description"], "color": s["color"],
                        "role": s["role"], "perms": sorted(P.PERMS[s["role"]]),
                        "timedOut": s["timeout_until"] > time.time(),
                        "channels": [channel_out(c, s["role"]) for c in chans]})
    discover = [{"id": s["id"], "name": s["name"], "description": s["description"], "color": s["color"],
                 "requiresCode": s["join_code_hash"] is not None}
                for s in app.db.q("SELECT * FROM servers WHERE id NOT IN (SELECT server_id FROM memberships WHERE user_id=?) "
                                  "ORDER BY name", (uid,))]
    return 200, {"servers": servers, "discover": discover}, None


def h_join(req):
    app = req.app
    sid = req.body.get("serverId")
    s = app.db.one("SELECT * FROM servers WHERE id=?", (sid,)) if isinstance(sid, str) else None
    if not s:
        raise ApiError(404, "Server not found.")
    if app.membership(s["id"], req.user["id"]):
        return 200, {"joined": True}, None
    if s["join_code_hash"]:
        if not app.rate_allowed(f"join:{req.user['id']}", 10, 60):
            raise ApiError(429, "Too many attempts. Try again shortly.")
        code = req.body.get("code")
        if not isinstance(code, str) or not hmac.compare_digest(hash_code(code.strip()), s["join_code_hash"]):
            raise ApiError(403, "That invite code isn't valid.")
    app.db.x("INSERT INTO memberships(server_id,user_id,role,joined_at) VALUES(?,?,?,?)",
             (s["id"], req.user["id"], "student", int(time.time() * 1000)))
    app.audit(s["id"], req.user["id"], "member_join", req.user["id"])
    app.hub.broadcast({"type": "member.update", "serverId": s["id"], "userId": req.user["id"]}, s["id"])
    return 200, {"joined": True}, None


def h_leave(req):
    (sid,) = req.args
    m = need_member(req, sid)
    if m["role"] == "owner":
        raise ApiError(403, "The Owner can't leave the server.")
    req.app.db.x("DELETE FROM memberships WHERE server_id=? AND user_id=?", (sid, req.user["id"]))
    req.app.hub.broadcast({"type": "member.update", "serverId": sid, "userId": req.user["id"]}, sid)
    return 204, None, None


def h_members(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "read")
    rows = req.app.db.q("SELECT u.id,u.name,u.bio,ms.role,ms.joined_at,ms.timeout_until FROM memberships ms "
                        "JOIN users u ON u.id=ms.user_id WHERE ms.server_id=?", (sid,))
    out = [{"id": r["id"], "name": r["name"], "bio": r["bio"], "role": r["role"], "joinedAt": r["joined_at"],
            "timedOut": r["timeout_until"] > time.time(), "online": req.app.hub.online(r["id"])} for r in rows]
    out.sort(key=lambda r: (-P.level(r["role"]), not r["online"], r["name"].lower()))
    return 200, {"members": out}, None


def h_set_role(req):
    sid, uid = req.args
    actor = need_member(req, sid)
    target = req.app.membership(sid, uid)
    if not target:
        raise ApiError(404, "Member not found.")
    new_role = role_key(req.body.get("role"), "")
    if uid == req.user["id"]:
        raise ApiError(403, "You can't change your own role.")
    if not P.can_assign(actor["role"], target["role"], new_role, False):
        raise ApiError(403, "You can't assign that role to this member.")
    req.app.db.x("UPDATE memberships SET role=? WHERE server_id=? AND user_id=?", (new_role, sid, uid))
    req.app.audit(sid, req.user["id"], "role_change", uid, f"{target['role']} -> {new_role}")
    req.app.hub.broadcast({"type": "member.update", "serverId": sid, "userId": uid}, sid)
    return 200, {"role": new_role}, None


def h_timeout(req):
    sid, uid = req.args
    actor = need_member(req, sid)
    need_perm(actor, "timeout_members")
    target = req.app.membership(sid, uid)
    if not target:
        raise ApiError(404, "Member not found.")
    if not P.can_moderate(actor["role"], target["role"], uid == req.user["id"]):
        raise ApiError(403, "You can't timeout this member.")
    minutes = req.body.get("minutes")
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 0 <= minutes <= 40320:
        raise ApiError(400, "Minutes must be between 0 and 40320 (0 clears a timeout).")
    until = int(time.time()) + minutes * 60 if minutes else 0
    req.app.db.x("UPDATE memberships SET timeout_until=? WHERE server_id=? AND user_id=?", (until, sid, uid))
    req.app.audit(sid, req.user["id"], "timeout" if minutes else "timeout_clear", uid, f"{minutes} min" if minutes else "")
    req.app.hub.broadcast({"type": "member.update", "serverId": sid, "userId": uid}, sid)
    return 200, {"timeoutMinutes": minutes}, None


def h_update_server(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "manage_server")
    name = clean_text(req.body.get("name"), 2, 32)
    desc = clean_text(req.body.get("description", ""), 0, 120) if req.body.get("description", "") != "" else ""
    if name is None or desc is None:
        raise ApiError(400, "Name must be 2–32 characters and the description up to 120.")
    req.app.db.x("UPDATE servers SET name=?, description=? WHERE id=?", (name, desc, sid))
    req.app.audit(sid, req.user["id"], "server_update")
    req.app.hub.broadcast({"type": "server.update", "serverId": sid}, sid)
    return 200, {"name": name, "description": desc}, None


def h_invite(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "manage_invites")
    if req.body.get("enabled") is True:
        code = secrets.token_urlsafe(9)
        req.app.db.x("UPDATE servers SET join_code_hash=? WHERE id=?", (hash_code(code), sid))
        req.app.audit(sid, req.user["id"], "invite_rotate")
        return 200, {"code": code}, None  # shown once; only the hash is stored
    req.app.db.x("UPDATE servers SET join_code_hash=NULL WHERE id=?", (sid,))
    req.app.audit(sid, req.user["id"], "invite_disable")
    return 200, {"code": None}, None


def h_create_channel(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "manage_channels")
    raw = req.body.get("name")
    name = re.sub(r"\s+", "-", raw.strip().lower()) if isinstance(raw, str) else ""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,31}", name):
        raise ApiError(400, "Channel names are 2–32 characters: lowercase letters, numbers and hyphens.")
    topic = clean_text(req.body.get("topic", ""), 0, 120) if req.body.get("topic", "") != "" else ""
    if topic is None:
        raise ApiError(400, "Topic must be 120 characters or fewer.")
    min_read, min_post = P.level(role_key(req.body.get("minRead"))), P.level(role_key(req.body.get("minPost")))
    if max(min_read, min_post) > P.level(m["role"]):
        raise ApiError(403, "You can't restrict a channel above your own role.")
    min_post = max(min_read, min_post)
    if req.app.db.one("SELECT 1 FROM channels WHERE server_id=? AND name=?", (sid, name)):
        raise ApiError(409, "A channel with that name already exists.")
    pos = (req.app.db.one("SELECT COALESCE(MAX(position),0)+1 AS p FROM channels WHERE server_id=?", (sid,)) or {"p": 0})["p"]
    cid = str(uuid.uuid4())
    req.app.db.x("INSERT INTO channels(id,server_id,name,topic,min_read,min_post,position) VALUES(?,?,?,?,?,?,?)",
                 (cid, sid, name, topic, min_read, min_post, pos))
    req.app.audit(sid, req.user["id"], "channel_create", None, f"#{name}")
    req.app.hub.broadcast({"type": "channel.update", "serverId": sid}, sid)
    return 201, {"id": cid}, None


def h_delete_channel(req):
    (cid,) = req.args
    ch, m = need_channel(req, cid)
    need_perm(m, "manage_channels")
    if req.app.db.one("SELECT COUNT(*) AS n FROM channels WHERE server_id=?", (ch["server_id"],))["n"] <= 1:
        raise ApiError(400, "A server needs at least one channel.")
    req.app.db.x("DELETE FROM channels WHERE id=?", (cid,))
    req.app.audit(ch["server_id"], req.user["id"], "channel_delete", None, f"#{ch['name']}")
    req.app.hub.broadcast({"type": "channel.update", "serverId": ch["server_id"]}, ch["server_id"])
    return 204, None, None


def h_history(req):
    (cid,) = req.args
    need_channel(req, cid)
    try:
        limit = min(50, max(1, int(req.query.get("limit", ["50"])[0])))
        before = int(req.query.get("before", ["0"])[0])
    except ValueError:
        raise ApiError(400, "Invalid pagination value.")
    sql, params = req.app.MSG_SQL + "WHERE m.channel_id=? AND m.deleted=0 ", [cid]
    if before > 0:
        sql, params = sql + "AND m.seq<? ", params + [before]
    rows = req.app.db.q(sql + "ORDER BY m.seq DESC LIMIT ?", tuple(params + [limit]))
    rows.reverse()
    return 200, {"messages": req.app.messages_out(rows)}, None


def h_send(req):
    (cid,) = req.args
    ch, m = need_channel(req, cid)
    if not P.has_perm(m["role"], "send") or P.level(m["role"]) < ch["min_post"]:
        raise ApiError(403, "You can't post in this channel.")
    not_timed_out(m)
    text = validate_message(req.body.get("text"))
    if not text:
        raise ApiError(400, "Messages must be 1–500 characters with no control characters.")
    problem = req.app.message_rate_allowed(req.user["id"], m["role"], text)
    if problem:
        raise ApiError(429, problem)
    mid = str(uuid.uuid4())
    req.app.db.x("INSERT INTO messages(id,channel_id,user_id,text,created_at) VALUES(?,?,?,?,?)",
                 (mid, cid, req.user["id"], text, int(time.time() * 1000)))
    out = req.app.message_out(mid)
    req.app.hub.broadcast({"type": "message.new", "serverId": ch["server_id"], "channelId": cid, "message": out},
                          ch["server_id"], cid)
    return 201, {"message": out}, None


def h_edit(req):
    (mid,) = req.args
    row, ch, m = need_message(req, mid)
    if row["user_id"] != req.user["id"]:
        raise ApiError(403, "You can only edit your own messages.")
    not_timed_out(m)
    text = validate_message(req.body.get("text"))
    if not text:
        raise ApiError(400, "Messages must be 1–500 characters with no control characters.")
    req.app.db.x("UPDATE messages SET text=?, edited_at=? WHERE id=?", (text, int(time.time() * 1000), mid))
    out = req.app.message_out(mid)
    req.app.hub.broadcast({"type": "message.edit", "serverId": ch["server_id"], "channelId": ch["id"], "message": out},
                          ch["server_id"], ch["id"])
    return 200, {"message": out}, None


def h_delete_msg(req):
    (mid,) = req.args
    row, ch, m = need_message(req, mid)
    own = row["user_id"] == req.user["id"]
    if not own:
        author = req.app.membership(ch["server_id"], row["user_id"])
        author_role = author["role"] if author else "student"
        if not P.has_perm(m["role"], "delete_messages") or not P.can_moderate(m["role"], author_role):
            raise ApiError(403, "You can't delete this message.")
    # Privacy: blank the text unless an open report still needs it for review.
    keep = req.app.db.one("SELECT 1 FROM reports WHERE message_id=? AND status='open'", (mid,))
    req.app.db.x("UPDATE messages SET deleted=1, text=? WHERE id=?", (row["text"] if keep else "", mid))
    if not own:
        req.app.audit(ch["server_id"], req.user["id"], "message_delete", row["user_id"], f"#{ch['name']}")
    req.app.hub.broadcast({"type": "message.delete", "serverId": ch["server_id"], "channelId": ch["id"], "messageId": mid},
                          ch["server_id"], ch["id"])
    return 204, None, None


def h_react(req):
    (mid,) = req.args
    row, ch, m = need_message(req, mid)
    need_perm(m, "react")
    not_timed_out(m)
    emoji = req.body.get("emoji")
    if emoji not in REACTIONS:
        raise ApiError(400, "Unsupported reaction.")
    uid = req.user["id"]
    if req.app.db.one("SELECT 1 FROM reactions WHERE message_id=? AND user_id=? AND emoji=?", (mid, uid, emoji)):
        req.app.db.x("DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?", (mid, uid, emoji))
    else:
        req.app.db.x("INSERT INTO reactions(message_id,user_id,emoji) VALUES(?,?,?)", (mid, uid, emoji))
    out = req.app.message_out(mid)
    req.app.hub.broadcast({"type": "reaction.update", "serverId": ch["server_id"], "channelId": ch["id"],
                           "messageId": mid, "reactions": out["reactions"]}, ch["server_id"], ch["id"])
    return 200, {"reactions": out["reactions"]}, None


def h_report(req):
    (mid,) = req.args
    row, ch, m = need_message(req, mid)
    need_perm(m, "report")
    reason = req.body.get("reason")
    if reason not in REPORT_REASONS:
        raise ApiError(400, "Choose a valid report reason.")
    if row["user_id"] == req.user["id"]:
        raise ApiError(400, "You can't report your own message.")
    if req.app.db.one("SELECT 1 FROM reports WHERE message_id=? AND reporter_id=?", (mid, req.user["id"])):
        return 200, {"received": True, "duplicate": True}, None
    req.app.db.x("INSERT INTO reports(id,message_id,reporter_id,reason,created_at) VALUES(?,?,?,?,?)",
                 (str(uuid.uuid4()), mid, req.user["id"], reason, int(time.time() * 1000)))
    return 202, {"received": True}, None


def h_reports(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "view_reports")
    status = req.query.get("status", ["open"])[0]
    if status not in {"open", "dismissed", "actioned"}:
        raise ApiError(400, "Invalid status.")
    can_resolve = P.has_perm(m["role"], "resolve_reports")
    rows = req.app.db.q(
        "SELECT r.id,r.reason,r.status,r.created_at,r.reporter_id,msg.id AS message_id,msg.text,msg.deleted,"
        "msg.user_id AS author_id,au.name AS author_name,c.name AS channel_name "
        "FROM reports r JOIN messages msg ON msg.id=r.message_id JOIN channels c ON c.id=msg.channel_id "
        "JOIN users au ON au.id=msg.user_id WHERE c.server_id=? AND r.status=? ORDER BY r.created_at DESC LIMIT 100",
        (sid, status))
    out = [{"id": r["id"], "reason": r["reason"], "status": r["status"], "createdAt": r["created_at"],
            "channel": r["channel_name"], "messageId": r["message_id"], "deleted": bool(r["deleted"]),
            "text": r["text"], "author": {"id": r["author_id"], "name": r["author_name"]},
            "reporterId": r["reporter_id"] if can_resolve else None} for r in rows]
    return 200, {"reports": out, "canResolve": can_resolve}, None


def h_resolve_report(req):
    (rid,) = req.args
    r = req.app.db.one("SELECT r.*, c.server_id FROM reports r JOIN messages msg ON msg.id=r.message_id "
                       "JOIN channels c ON c.id=msg.channel_id WHERE r.id=?", (rid,))
    if not r:
        raise ApiError(404, "Report not found.")
    m = need_member(req, r["server_id"])
    need_perm(m, "resolve_reports")
    action = req.body.get("action")
    if action not in {"dismissed", "actioned"}:
        raise ApiError(400, "Action must be 'dismissed' or 'actioned'.")
    req.app.db.x("UPDATE reports SET status=?, resolved_by=?, resolved_at=? WHERE id=?",
                 (action, req.user["id"], int(time.time() * 1000), rid))
    req.app.audit(r["server_id"], req.user["id"], "report_" + action, None, "")
    return 200, {"status": action}, None


def h_audit(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "view_audit")
    rows = req.app.db.q(
        "SELECT a.action,a.detail,a.created_at,au.name AS actor,tu.name AS target FROM audit_log a "
        "JOIN users au ON au.id=a.actor_id LEFT JOIN users tu ON tu.id=a.target_id "
        "WHERE a.server_id=? ORDER BY a.id DESC LIMIT 100", (sid,))
    return 200, {"entries": [{"action": r["action"], "detail": r["detail"], "createdAt": r["created_at"],
                              "actor": r["actor"], "target": r["target"]} for r in rows]}, None


def h_diagnostics(req):
    (sid,) = req.args
    m = need_member(req, sid)
    need_perm(m, "view_diagnostics")
    d = req.app.db
    one = lambda sql: d.one(sql, (sid,))["n"]  # noqa: E731 - aggregate counts only, never message content
    return 200, {
        "members": one("SELECT COUNT(*) AS n FROM memberships WHERE server_id=?"),
        "channels": one("SELECT COUNT(*) AS n FROM channels WHERE server_id=?"),
        "messages": one("SELECT COUNT(*) AS n FROM messages m JOIN channels c ON c.id=m.channel_id WHERE c.server_id=? AND m.deleted=0"),
        "openReports": one("SELECT COUNT(*) AS n FROM reports r JOIN messages m ON m.id=r.message_id JOIN channels c ON c.id=m.channel_id WHERE c.server_id=? AND r.status='open'"),
        "liveConnections": req.app.hub.total(), "uptimeSeconds": int(time.time() - req.app.started),
        "mode": "demo" if req.app.demo_mode else "school-auth-required"}, None


ROUTES = [  # (method, regex, handler, needs_auth)
    ("GET", r"/api/health", h_health, False),
    ("GET", r"/api/meta", h_meta, False),
    ("GET", r"/api/session", h_session, False),
    ("POST", r"/api/demo-session", h_demo_session, False),
    ("POST", r"/api/logout", h_logout, False),
    ("PATCH", r"/api/me", h_update_me, True),
    ("GET", r"/api/servers", h_servers, True),
    ("POST", r"/api/servers/join", h_join, True),
    ("POST", rf"/api/servers/{UUID_RE}/leave", h_leave, True),
    ("PATCH", rf"/api/servers/{UUID_RE}", h_update_server, True),
    ("POST", rf"/api/servers/{UUID_RE}/invite", h_invite, True),
    ("GET", rf"/api/servers/{UUID_RE}/members", h_members, True),
    ("POST", rf"/api/servers/{UUID_RE}/members/{UUID_RE}/role", h_set_role, True),
    ("POST", rf"/api/servers/{UUID_RE}/members/{UUID_RE}/timeout", h_timeout, True),
    ("POST", rf"/api/servers/{UUID_RE}/channels", h_create_channel, True),
    ("GET", rf"/api/servers/{UUID_RE}/reports", h_reports, True),
    ("GET", rf"/api/servers/{UUID_RE}/audit", h_audit, True),
    ("GET", rf"/api/servers/{UUID_RE}/diagnostics", h_diagnostics, True),
    ("DELETE", rf"/api/channels/{UUID_RE}", h_delete_channel, True),
    ("GET", rf"/api/channels/{UUID_RE}/messages", h_history, True),
    ("POST", rf"/api/channels/{UUID_RE}/messages", h_send, True),
    ("PATCH", rf"/api/messages/{UUID_RE}", h_edit, True),
    ("DELETE", rf"/api/messages/{UUID_RE}", h_delete_msg, True),
    ("POST", rf"/api/messages/{UUID_RE}/reactions", h_react, True),
    ("POST", rf"/api/messages/{UUID_RE}/report", h_report, True),
    ("POST", rf"/api/reports/{UUID_RE}/resolve", h_resolve_report, True),
]
COMPILED = [(m, re.compile(p), fn, auth) for m, p, fn, auth in ROUTES]


# --------------------------------------------------------------------------- HTTP handler
class Handler(BaseHTTPRequestHandler):
    server_version = "BCPSChatPython/2.0"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; "
                         "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; "
                         "object-src 'none'; script-src 'self'; style-src 'self'")

    def _send_json(self, status: int, data: object | None, extra: dict | None = None) -> None:
        body = b"" if data is None else json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "Invalid Content-Length.")
        if length < 0 or length > MAX_HTTP_BODY:
            self.close_connection = True
            raise ApiError(413, "Request body is too large.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "Request body must be valid JSON.")
        if not isinstance(data, dict):
            raise ApiError(400, "Request body must be a JSON object.")
        return data

    def _send_static(self, path: str) -> None:
        decoded = unquote(path)
        relative = "index.html" if decoded == "/" else decoded.lstrip("/")
        requested = (PUBLIC_DIR / relative).resolve()
        if not requested.is_relative_to(PUBLIC_DIR):
            return self._send_json(403, {"error": "Forbidden."})
        if not requested.is_file():
            return self._send_json(404, {"error": "Not found."})
        content = requested.read_bytes()
        ctype = mimetypes.guess_type(requested.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in {"application/javascript", "application/json"}:
            ctype += "; charset=utf-8"
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "public, max-age=3600" if self.app.production else "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        app, peer = self.app, self.client_address[0]
        try:
            if not app.rate_allowed(f"http:{peer}", 1200, 60):
                self.close_connection = True
                raise ApiError(429, "Too many requests. Try again shortly.")
            parsed = urlsplit(self.path)
            path = parsed.path
            if method == "GET" and path == "/ws":
                return self._websocket()
            if not path.startswith("/api/"):
                if method == "GET":
                    return self._send_static(path)
                self.close_connection = True
                raise ApiError(405, "Method not allowed.")
            match = None
            for m, rx, fn, auth in COMPILED:
                hit = rx.fullmatch(path)
                if hit and m == method:
                    match = (fn, auth, hit.groups())
                    break
            if not match:
                self.close_connection = True
                raise ApiError(404, "Not found.")
            fn, auth, args = match
            body: dict = {}
            if method != "GET":
                if not app.origin_ok(self.headers.get("Origin"), self.headers.get("Host", "")):
                    self.close_connection = True
                    raise ApiError(403, "Invalid request origin.")
                body = self._read_json()
            user = None
            if auth:
                user = app.user_from_cookie(self.headers.get("Cookie"))
                if not user:
                    raise ApiError(401, "Sign in to the local demo room first.")
            status, data, headers = fn(Req(app, method, user, body, parse_qs(parsed.query), args, peer, self.headers))
            self._send_json(status, data, headers)
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.message}, exc.headers)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001 - never leak internals to the client
            logging.exception("Unhandled error")
            self.close_connection = True
            self._send_json(500, {"error": "Something went wrong."})

    # ---- WebSocket endpoint
    def _read_exact(self, n: int) -> bytes:
        data = self.rfile.read(n)
        if len(data) < n:
            raise EOFError
        return data

    def _websocket(self) -> None:
        app = self.app
        if self.headers.get("Upgrade", "").lower() != "websocket" or "upgrade" not in self.headers.get("Connection", "").lower():
            raise ApiError(400, "WebSocket upgrade required.")
        if not app.origin_ok(self.headers.get("Origin"), self.headers.get("Host", "")):
            self.close_connection = True
            raise ApiError(403, "Invalid request origin.")
        user = app.user_from_cookie(self.headers.get("Cookie"))
        if not user:
            self.close_connection = True
            raise ApiError(401, "Sign in first.")
        key = self.headers.get("Sec-WebSocket-Key")
        if not key or self.headers.get("Sec-WebSocket-Version") != "13":
            raise ApiError(400, "Bad WebSocket handshake.")
        if app.hub.count_for(user["id"]) >= 5:
            self.close_connection = True
            raise ApiError(429, "Too many open connections.")
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.wfile.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        self.wfile.flush()
        self.close_connection = True
        self.connection.settimeout(90)
        conn = WSConn(self, user["id"])
        app.hub.add(conn)
        conn.send({"type": "ready"})
        app.hub.presence(user["id"])
        try:
            while conn.alive:
                b1, b2 = self._read_exact(2)
                opcode, masked, length = b1 & 0x0F, b2 & 0x80, b2 & 0x7F
                if length == 126:
                    length = struct.unpack("!H", self._read_exact(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", self._read_exact(8))[0]
                if not masked or not (b1 & 0x80) or opcode == 0 or length > 4096:
                    conn.send_raw(ws_frame(0x8, struct.pack("!H", 1002)))
                    break
                mask = self._read_exact(4)
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read_exact(length)))
                if opcode == 0x8:
                    conn.send_raw(ws_frame(0x8, payload[:2]))
                    break
                if opcode == 0x9:
                    conn.send_raw(ws_frame(0xA, payload))
                elif opcode == 0x1:
                    conn.send({"type": "pong"})  # clients only send keep-alive pings; nothing else is trusted
        except (OSError, EOFError):
            pass
        finally:
            conn.alive = False
            app.hub.remove(conn)
            app.hub.presence(user["id"])


class ChatServer(ThreadingHTTPServer):
    daemon_threads = True
    app: App


def create_server(app: App, host: str, port: int) -> ChatServer:
    server = ChatServer((host, port), Handler)
    server.app = app
    return server


def main() -> None:
    load_dotenv(ROOT / ".env")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    demo = os.getenv("DEMO_MODE", "true").lower() == "true"
    production = os.getenv("APP_ENV", "development").lower() == "production"
    secret = os.getenv("SESSION_SECRET", "")
    if not secret and not production:
        secret_file = ROOT / "data" / ".dev_session_secret"
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        if not secret_file.exists():
            secret_file.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        secret = secret_file.read_text(encoding="utf-8").strip()
        logging.warning("SESSION_SECRET not set; using a generated development secret in data/.dev_session_secret.")
    origins = {i.strip().rstrip("/") for i in os.getenv("ALLOWED_ORIGINS", "").split(",") if i.strip()}
    db_url = os.getenv("DATABASE_URL", "")
    if db_url and not db_url.startswith("sqlite:///"):
        raise RuntimeError("Only SQLite is implemented. PostgreSQL needs a new Database adapter (see README).")
    db_path = db_url.replace("sqlite:///", "", 1) if db_url else str(ROOT / "data" / "chat.db")
    app = App(db_path, secret, demo, production, origins, os.getenv("OWNER_CLAIM_CODE") or None)
    host, port = os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "3000"))
    server = create_server(app, host, port)
    print(f"BCPS chatroom: http://{host}:{port}")
    print("Mode: LOCAL DEMO ONLY - demo display names do not verify student identity" if demo
          else "Mode: school authentication required / not yet integrated")
    if app.owner_code:
        print(f"\nOwner claim code (single use, type it in the sign-in screen): {app.owner_code}")
    for name, code in app.seed_codes.items():
        print(f"Invite code for '{name}' (shown once): {code}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping chat server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
