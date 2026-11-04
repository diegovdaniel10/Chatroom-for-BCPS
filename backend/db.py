"""SQLite data layer. All SQL lives here and in server.py using portable SQL with `?`
placeholders, so a PostgreSQL adapter (e.g. psycopg with `%s` placeholders) can replace
`Database` later without touching the HTTP layer."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, name_lower TEXT NOT NULL UNIQUE,
  bio TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS servers(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  color TEXT NOT NULL, join_code_hash TEXT, auto_join INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS memberships(
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'student', timeout_until INTEGER NOT NULL DEFAULT 0,
  joined_at INTEGER NOT NULL, PRIMARY KEY(server_id, user_id));
CREATE TABLE IF NOT EXISTS channels(
  id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name TEXT NOT NULL, topic TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'text',
  min_read INTEGER NOT NULL DEFAULT 1, min_post INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0, UNIQUE(server_id, name));
CREATE TABLE IF NOT EXISTS messages(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id), text TEXT NOT NULL,
  created_at INTEGER NOT NULL, edited_at INTEGER, deleted INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, seq);
CREATE TABLE IF NOT EXISTS reactions(
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL, emoji TEXT NOT NULL, PRIMARY KEY(message_id, user_id, emoji));
CREATE TABLE IF NOT EXISTS reports(
  id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  reporter_id TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL, resolved_by TEXT, resolved_at INTEGER,
  UNIQUE(message_id, reporter_id));
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL, actor_id TEXT NOT NULL,
  action TEXT NOT NULL, target_id TEXT, detail TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
"""


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class Database:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def q(self, sql: str, params: tuple = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.q(sql, params)
        return rows[0] if rows else None

    def x(self, sql: str, params: tuple = ()) -> int:
        with self.lock:
            return self.conn.execute(sql, params).lastrowid

    @contextmanager
    def tx(self):
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")


def seed(db: Database) -> dict[str, str]:
    """Create example servers/channels on first run. Returns one-time invite codes."""
    codes: dict[str, str] = {}
    if db.one("SELECT 1 FROM servers"):
        return codes
    now = int(time.time() * 1000)
    layout = [
        ("BCPS Hub", "The main hangout for BCPS students.", "#5b6cff", True, False, [
            ("general", "Chat about anything school-appropriate.", 1, 1),
            ("announcements", "Official news. Moderators and above can post.", 1, 4),
            ("homework-help", "Ask for and give homework help.", 1, 1),
            ("school-talk", "Classes, events and school life.", 1, 1),
            ("gaming", "Games and game nights.", 1, 1),
            ("clubs", "Find and promote school clubs.", 1, 1),
            ("questions", "Questions about the server or school.", 1, 1),
            ("staff-lounge", "Helpers and above only.", 3, 3),
        ]),
        ("Clubs Corner", "Space for clubs and activities.", "#1fb6a6", True, False, [
            ("general", "Club chat.", 1, 1), ("robotics", "Robotics team.", 1, 1), ("art", "Art club.", 1, 1)]),
        ("Staff Room", "Invite-only space for staff roles.", "#e0527a", False, True, [
            ("staff-chat", "Private staff discussion.", 1, 1)]),
    ]
    for name, desc, color, auto_join, invite_only, chans in layout:
        sid = str(uuid.uuid4())
        code_hash = None
        if invite_only:
            codes[name] = secrets.token_urlsafe(9)
            code_hash = hash_code(codes[name])
        db.x("INSERT INTO servers(id,name,description,color,join_code_hash,auto_join,created_at) VALUES(?,?,?,?,?,?,?)",
             (sid, name, desc, color, code_hash, 1 if auto_join else 0, now))
        for pos, (cname, topic, min_read, min_post) in enumerate(chans):
            db.x("INSERT INTO channels(id,server_id,name,topic,min_read,min_post,position) VALUES(?,?,?,?,?,?,?)",
                 (str(uuid.uuid4()), sid, cname, topic, min_read, min_post, pos))
    return codes
