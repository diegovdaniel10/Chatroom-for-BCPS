import base64
import http.client
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import permissions as P  # noqa: E402
import server as S  # noqa: E402
from security import normalize_display_name, sign_session, validate_message, verify_session  # noqa: E402

OWNER_CODE = "test-owner-code"


class Client:
    def __init__(self, port):
        self.port, self.cookie, self.user = port, None, None

    def req(self, method, path, body=None, origin=True, cookie=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if origin and method != "GET":
            headers["Origin"] = f"http://127.0.0.1:{self.port}"
        if cookie and self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = conn.getresponse()
        raw = r.read()
        data = json.loads(raw) if raw else None
        sc = r.getheader("Set-Cookie")
        if sc and sc.split("=", 1)[1].split(";")[0]:
            self.cookie = sc.split(";")[0]
        hdrs = dict(r.getheaders())
        conn.close()
        return r.status, data, hdrs

    def login(self, name, owner_code=None):
        body = {"name": name}
        if owner_code:
            body["ownerCode"] = owner_code
        status, data, _ = self.req("POST", "/api/demo-session", body)
        assert status == 200, (status, data)
        self.user = data["student"]
        return self


class WSClient:
    def __init__(self, port, cookie, origin=True):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = ["GET /ws HTTP/1.1", f"Host: 127.0.0.1:{port}", "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        if origin:
            lines.append(f"Origin: http://127.0.0.1:{port}")
        if cookie:
            lines.append(f"Cookie: {cookie}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, self.rest = buf.partition(b"\r\n\r\n")
        self.status = int(head.split()[1])

    def _read(self, n):
        while len(self.rest) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError
            self.rest += chunk
        out, self.rest = self.rest[:n], self.rest[n:]
        return out

    def recv(self, timeout=3):
        self.sock.settimeout(timeout)
        b1, b2 = self._read(2)
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read(2))[0]
        return b1 & 0x0F, self._read(length)

    def next_event(self, timeout=3):
        end = time.time() + timeout
        while time.time() < end:
            op, payload = self.recv(max(0.1, end - time.time()))
            if op == 0x1:
                return json.loads(payload)
        return None

    def close(self):
        self.sock.close()


class Base(unittest.TestCase):
    n = 0

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.app = S.App(str(Path(cls.tmp.name) / "t.db"), "x" * 48, demo_mode=True, owner_code=OWNER_CODE)
        cls.app.login_limit = 10000
        cls.server = S.create_server(cls.app, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.owner = Client(cls.port).login("Dana K", OWNER_CODE)
        _, data, _ = cls.owner.req("GET", "/api/servers")
        cls.hub = next(s for s in data["servers"] if s["name"] == "BCPS Hub")
        cls.sid = cls.hub["id"]
        cls.ch = {c["name"]: c["id"] for c in cls.hub["channels"]}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def user(self, role="online"):
        Base.n += 1
        c = Client(self.port).login(f"Tester {Base.n}")
        if role != "online":
            self.app.db.x("UPDATE memberships SET role=? WHERE server_id=? AND user_id=?", (role, self.sid, c.user["id"]))
        return c

    def say(self, client, text="hello", channel="global-chat"):
        return client.req("POST", f"/api/channels/{self.ch[channel]}/messages", {"text": text})


class RoleTests(unittest.TestCase):
    def test_roles_in_exact_order(self):
        self.assertEqual(P.ROLES, [
            "offline", "online", "normie", "rookie", "star", "champion", "lucky", "legend",
            "vip", "mvps", "low_moderator", "moderator", "low_admin", "admin",
            "super_admin", "developer", "co_owner", "owner"])
        self.assertEqual([P.level(r) for r in P.ROLES], list(range(1, 19)))

    def test_distinct_colors_and_badges(self):
        hierarchy_info = {k: P.ROLE_INFO[k] for k in P.ROLES}
        self.assertEqual(len({v["color"] for v in hierarchy_info.values()}), 18)
        self.assertEqual(len({v["badge"] for v in hierarchy_info.values()}), 18)

    def test_permission_matrix(self):
        # offline is read-only
        self.assertEqual(P.PERMS["offline"], frozenset({"read"}))
        # all roles above offline have base permissions
        for r in P.ROLES:
            if r == "offline":
                continue
            self.assertTrue({"read", "send", "react", "report"} <= P.PERMS[r], r)
        self.assertFalse(P.has_perm("online", "delete_messages"))
        self.assertFalse(P.has_perm("low_moderator", "delete_messages"))
        self.assertTrue(P.has_perm("low_moderator", "view_reports"))
        self.assertFalse(P.has_perm("low_moderator", "resolve_reports"))
        for p in ("delete_messages", "timeout_members", "resolve_reports"):
            self.assertTrue(P.has_perm("moderator", p))
        self.assertFalse(P.has_perm("moderator", "manage_channels"))
        for p in ("manage_channels", "manage_server", "manage_roles"):
            self.assertTrue(P.has_perm("admin", p))
        self.assertFalse(P.has_perm("admin", "view_audit"))
        # Developer: diagnostics only, no moderation/owner powers
        self.assertTrue(P.has_perm("developer", "view_diagnostics"))
        for p in ("delete_messages", "timeout_members", "manage_roles", "manage_channels", "manage_invites"):
            self.assertFalse(P.has_perm("developer", p))
        self.assertTrue(P.has_perm("super_admin", "view_audit"))
        self.assertFalse(P.has_perm("super_admin", "manage_invites"))
        self.assertTrue(P.has_perm("co_owner", "manage_invites"))
        self.assertTrue(P.has_perm("owner", "manage_invites"))

    def test_wheel_outcomes(self):
        keys = [o["key"] for o in P.WHEEL_OUTCOMES]
        # Never includes moderation/admin roles
        forbidden = {"low_moderator", "moderator", "low_admin", "admin", "super_admin",
                     "developer", "co_owner", "owner"}
        self.assertFalse(forbidden & set(keys))
        # Includes the four VIP/MVPS prizes
        self.assertIn("vip_1day", keys)
        self.assertIn("mvps_1day", keys)
        self.assertIn("vip_forever", keys)
        self.assertIn("mvps_forever", keys)
        # 1-day prizes have 86400 duration; forever prizes have 0
        for o in P.WHEEL_OUTCOMES:
            if "1day" in o["key"]:
                self.assertEqual(o["duration"], 86400)
            elif "forever" in o["key"]:
                self.assertEqual(o["duration"], 0)

    def test_assignment_rules(self):
        self.assertFalse(P.can_assign("owner", "online", "owner", False))      # nobody can be made Owner
        self.assertFalse(P.can_assign("owner", "owner", "admin", False))        # Owner can't be demoted
        self.assertFalse(P.can_assign("owner", "online", "admin", True))       # never yourself
        self.assertTrue(P.can_assign("owner", "online", "co_owner", False))
        self.assertFalse(P.can_assign("co_owner", "online", "co_owner", False))
        self.assertTrue(P.can_assign("co_owner", "online", "super_admin", False))
        self.assertFalse(P.can_assign("super_admin", "online", "super_admin", False))
        self.assertTrue(P.can_assign("super_admin", "admin", "low_admin", False))
        self.assertFalse(P.can_assign("admin", "online", "admin", False))
        self.assertTrue(P.can_assign("admin", "online", "moderator", False))
        self.assertFalse(P.can_assign("developer", "online", "normie", False))  # no manage_roles
        self.assertFalse(P.can_assign("moderator", "online", "low_moderator", False))


class SecurityTests(unittest.TestCase):
    def test_session_signing(self):
        tok = sign_session({"id": "a", "expiresAt": time.time() + 60}, "s" * 40)
        self.assertEqual(verify_session(tok, "s" * 40)["id"], "a")
        self.assertIsNone(verify_session(tok, "t" * 40))
        self.assertIsNone(verify_session(tok[:-2] + "xx", "s" * 40))
        self.assertIsNone(verify_session(sign_session({"id": "a", "expiresAt": time.time() - 1}, "s" * 40), "s" * 40))

    def test_validation(self):
        self.assertEqual(normalize_display_name("  Sam   Lee "), "Sam Lee")
        for bad in ("a", "x" * 25, "<script>", "Admin", "Mr Moderator", "Owner", None, 5):
            self.assertIsNone(normalize_display_name(bad), bad)
        self.assertEqual(validate_message("hi <b>there</b>"), "hi <b>there</b>")
        for bad in ("", "   ", "x" * 501, "a\x00b", "a\u202eb", None, 3):
            self.assertIsNone(validate_message(bad), bad)

    def test_production_guards(self):
        # Short secret in production raises RuntimeError
        with self.assertRaises(RuntimeError):
            S.App(":memory:", "short", demo_mode=False, production=True)
        # Valid secret in production with demo mode is allowed (warning only)
        app = S.App(":memory:", "x" * 48, demo_mode=True, production=True)
        self.assertTrue(app.production)


class ApiTests(Base):
    def test_auth_and_origin(self):
        c = Client(self.port)
        self.assertEqual(c.req("GET", "/api/servers")[0], 401)
        self.assertEqual(c.req("POST", "/api/demo-session", {"name": "NoOrigin"}, origin=False)[0], 403)
        u = self.user()
        u.cookie = u.cookie[:-3] + "abc"  # tampered signature
        self.assertEqual(u.req("GET", "/api/servers")[0], 401)
        self.assertEqual(Client(self.port).req("GET", "/api/session")[0], 401)

    def test_security_headers_and_static(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/")
        r = conn.getresponse()
        r.read()
        self.assertEqual(r.status, 200)
        self.assertIn("script-src 'self'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        conn.request("GET", "/..%2f..%2fbackend/server.py")
        r = conn.getresponse()
        r.read()
        self.assertIn(r.status, (403, 404))

    def test_demo_name_taken_and_owner_claim_single_use(self):
        c = Client(self.port)
        self.assertEqual(c.req("POST", "/api/demo-session", {"name": "Dana K"})[0], 409)
        self.assertEqual(c.req("POST", "/api/demo-session", {"name": "Claimer", "ownerCode": OWNER_CODE})[0], 403)  # already used
        self.assertEqual(c.req("POST", "/api/demo-session", {"name": "Reserved Admin"})[0], 400)

    def test_wrong_owner_code_creates_nothing(self):
        app2 = S.App(":memory:", "y" * 48, owner_code="right-code")
        srv = S.create_server(app2, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = Client(srv.server_address[1])
            self.assertEqual(c.req("POST", "/api/demo-session", {"name": "Hopeful", "ownerCode": "wrong"})[0], 403)
            self.assertIsNone(app2.db.one("SELECT 1 FROM users WHERE name_lower='hopeful'"))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_login_rate_limit(self):
        app2 = S.App(":memory:", "z" * 48)
        app2.login_limit = 3
        srv = S.create_server(app2, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = Client(srv.server_address[1])
            codes = [c.req("POST", "/api/demo-session", {"name": f"Spam {i}"})[0] for i in range(5)]
            self.assertEqual(codes, [200, 200, 200, 429, 429])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_new_users_are_online_only_in_open_servers(self):
        u = self.user()
        _, data, _ = u.req("GET", "/api/servers")
        names = {s["name"]: s for s in data["servers"]}
        self.assertEqual(set(names), {"BCPS Hub", "Clubs Corner"})
        self.assertTrue(all(s["role"] == "online" for s in names.values()))
        self.assertEqual([d["name"] for d in data["discover"]], ["Staff Room"])
        self.assertNotIn("staff-lounge", [c["name"] for c in names["BCPS Hub"]["channels"]])

    def test_cannot_self_promote(self):
        u = self.user()
        for role in ("admin", "owner", "moderator", "normie"):
            s, d, _ = u.req("POST", f"/api/servers/{self.sid}/members/{u.user['id']}/role", {"role": role})
            self.assertEqual(s, 403, (role, d))
        self.assertEqual(self.app.membership(self.sid, u.user["id"])["role"], "online")
        admin = self.user("admin")
        self.assertEqual(admin.req("POST", f"/api/servers/{self.sid}/members/{admin.user['id']}/role", {"role": "owner"})[0], 403)
        self.assertEqual(self.app.membership(self.sid, admin.user["id"])["role"], "admin")

    def test_role_assignment_enforced(self):
        target = self.user()
        path = f"/api/servers/{self.sid}/members/{target.user['id']}/role"
        online_user, mod, dev = self.user(), self.user("moderator"), self.user("developer")
        self.assertEqual(online_user.req("POST", path, {"role": "normie"})[0], 403)
        self.assertEqual(mod.req("POST", path, {"role": "normie"})[0], 403)
        self.assertEqual(dev.req("POST", path, {"role": "normie"})[0], 403)
        admin = self.user("admin")
        self.assertEqual(admin.req("POST", path, {"role": "admin"})[0], 403)
        self.assertEqual(admin.req("POST", path, {"role": "owner"})[0], 403)
        self.assertEqual(admin.req("POST", path, {"role": "bogus"})[0], 400)
        self.assertEqual(admin.req("POST", path, {"role": "moderator"})[0], 200)
        # admin can't touch someone at/above their level
        self.assertEqual(admin.req("POST", f"/api/servers/{self.sid}/members/{dev.user['id']}/role", {"role": "online"})[0], 403)
        self.assertEqual(admin.req("POST", f"/api/servers/{self.sid}/members/{self.owner.user['id']}/role", {"role": "online"})[0], 403)
        # only Owner can grant Co-Owner; co-owner and super admin cannot
        sa, co = self.user("super_admin"), self.user("co_owner")
        self.assertEqual(sa.req("POST", path, {"role": "co_owner"})[0], 403)
        self.assertEqual(co.req("POST", path, {"role": "co_owner"})[0], 403)
        self.assertEqual(co.req("POST", path, {"role": "super_admin"})[0], 200)
        self.assertEqual(self.owner.req("POST", path, {"role": "co_owner"})[0], 200)
        self.assertEqual(self.owner.req("POST", path, {"role": "owner"})[0], 403)

    def test_all_roles_assignable_by_owner(self):
        t = self.user()
        for role in P.ROLES[:-1]:
            s, _, _ = self.owner.req("POST", f"/api/servers/{self.sid}/members/{t.user['id']}/role", {"role": role})
            self.assertEqual(s, 200, role)
            _, data, _ = self.owner.req("GET", f"/api/servers/{self.sid}/members")
            self.assertEqual(next(m for m in data["members"] if m["id"] == t.user["id"])["role"], role)
            _, srv, _ = t.req("GET", "/api/servers")
            hub = next(s for s in srv["servers"] if s["id"] == self.sid)
            self.assertEqual(hub["role"], role)
            self.assertEqual(set(hub["perms"]), set(P.PERMS[role]))

    def test_restricted_channels(self):
        online_user, low_mod, mod = self.user(), self.user("low_moderator"), self.user("moderator")
        self.assertEqual(online_user.req("GET", f"/api/channels/{self.ch['staff-lounge']}/messages")[0], 404)
        self.assertEqual(self.say(online_user, "sneaky", "staff-lounge")[0], 404)
        self.assertEqual(low_mod.req("GET", f"/api/channels/{self.ch['staff-lounge']}/messages")[0], 200)
        self.assertEqual(self.say(low_mod, "hi staff", "staff-lounge")[0], 201)
        self.assertEqual(self.say(online_user, "hi", "announcements")[0], 403)   # read-only for online
        self.assertEqual(self.say(low_mod, "hi", "announcements")[0], 403)
        self.assertEqual(self.say(mod, "News!", "announcements")[0], 201)
        # non-member of a server can't read or post
        outsider = self.user()
        staff_room = next(d for d in outsider.req("GET", "/api/servers")[1]["discover"] if d["name"] == "Staff Room")
        self.assertEqual(outsider.req("GET", f"/api/servers/{staff_room['id']}/members")[0], 404)
        self.assertEqual(outsider.req("POST", "/api/servers/join", {"serverId": staff_room["id"], "code": "nope"})[0], 403)
        self.assertEqual(outsider.req("POST", "/api/servers/join", {"serverId": staff_room["id"]})[0], 403)

    def test_invite_code_flow(self):
        staff = next(s for s in self.owner.req("GET", "/api/servers")[1]["servers"] if s["name"] == "Staff Room")
        s, d, _ = self.owner.req("POST", f"/api/servers/{staff['id']}/invite", {"enabled": True})
        self.assertEqual(s, 200)
        u = self.user()
        self.assertEqual(u.req("POST", "/api/servers/join", {"serverId": staff["id"], "code": d["code"]})[0], 200)
        self.assertEqual(self.user("admin").req("POST", f"/api/servers/{self.sid}/invite", {"enabled": True})[0], 403)

    def test_messages_edit_delete(self):
        a, b, mod = self.user(), self.user(), self.user("moderator")
        s, d, _ = self.say(a, "first <script>alert(1)</script>")
        self.assertEqual(s, 201)
        mid = d["message"]["id"]
        self.assertEqual(d["message"]["text"], "first <script>alert(1)</script>")  # stored verbatim; UI uses textContent
        self.assertEqual(b.req("PATCH", f"/api/messages/{mid}", {"text": "hijack"})[0], 403)
        self.assertEqual(mod.req("PATCH", f"/api/messages/{mid}", {"text": "hijack"})[0], 403)
        s, d, _ = a.req("PATCH", f"/api/messages/{mid}", {"text": "edited"})
        self.assertEqual((s, d["message"]["text"]), (200, "edited"))
        self.assertIsNotNone(d["message"]["editedAt"])
        self.assertEqual(b.req("DELETE", f"/api/messages/{mid}")[0], 403)
        self.assertEqual(mod.req("DELETE", f"/api/messages/{mid}")[0], 204)
        self.assertEqual(a.req("DELETE", f"/api/messages/{mid}")[0], 404)
        _, hist, _ = a.req("GET", f"/api/channels/{self.ch['global-chat']}/messages")
        self.assertNotIn(mid, [m["id"] for m in hist["messages"]])
        # moderators can't delete messages from equal/higher roles; authors can delete their own
        m2 = self.user("moderator")
        mid2 = self.say(m2, "mod msg")[1]["message"]["id"]
        self.assertEqual(mod.req("DELETE", f"/api/messages/{mid2}")[0], 403)
        self.assertEqual(m2.req("DELETE", f"/api/messages/{mid2}")[0], 204)

    def test_validation_errors(self):
        u = self.user()
        for bad in ("", "x" * 501, "bad\x00", 12):
            self.assertEqual(self.say(u, bad)[0], 400)
        big = u.req("POST", f"/api/channels/{self.ch['global-chat']}/messages", {"text": "x" * 9000})
        self.assertEqual(big[0], 413)

    def test_reactions_and_reports(self):
        a, b, low_mod, mod = self.user(), self.user(), self.user("low_moderator"), self.user("moderator")
        mid = self.say(a, "report me")[1]["message"]["id"]
        s, d, _ = b.req("POST", f"/api/messages/{mid}/reactions", {"emoji": "👍"})
        self.assertEqual((s, d["reactions"][0]["emoji"]), (200, "👍"))
        _, d, _ = b.req("POST", f"/api/messages/{mid}/reactions", {"emoji": "👍"})
        self.assertEqual(d["reactions"], [])
        self.assertEqual(b.req("POST", f"/api/messages/{mid}/reactions", {"emoji": "💩"})[0], 400)
        self.assertEqual(a.req("POST", f"/api/messages/{mid}/report", {"reason": "spam"})[0], 400)  # own message
        self.assertEqual(b.req("POST", f"/api/messages/{mid}/report", {"reason": "nonsense"})[0], 400)
        self.assertEqual(b.req("POST", f"/api/messages/{mid}/report", {"reason": "bullying"})[0], 202)
        self.assertEqual(b.req("POST", f"/api/messages/{mid}/report", {"reason": "bullying"})[1]["duplicate"], True)
        self.assertEqual(b.req("GET", f"/api/servers/{self.sid}/reports")[0], 403)
        _, rep, _ = low_mod.req("GET", f"/api/servers/{self.sid}/reports")
        mine = next(r for r in rep["reports"] if r["messageId"] == mid)
        self.assertIsNone(mine["reporterId"])  # reporter identity hidden from low moderators
        rid = mine["id"]
        self.assertEqual(low_mod.req("POST", f"/api/reports/{rid}/resolve", {"action": "dismissed"})[0], 403)
        _, rep, _ = mod.req("GET", f"/api/servers/{self.sid}/reports")
        self.assertEqual(next(r for r in rep["reports"] if r["id"] == rid)["reporterId"], b.user["id"])
        # deleting a reported message keeps its text for review only
        self.assertEqual(a.req("DELETE", f"/api/messages/{mid}")[0], 204)
        _, rep, _ = mod.req("GET", f"/api/servers/{self.sid}/reports")
        self.assertEqual(next(r for r in rep["reports"] if r["id"] == rid)["text"], "report me")
        self.assertEqual(mod.req("POST", f"/api/reports/{rid}/resolve", {"action": "actioned"})[0], 200)
        self.assertNotIn(rid, [r["id"] for r in mod.req("GET", f"/api/servers/{self.sid}/reports")[1]["reports"]])

    def test_timeouts(self):
        target, mod, online_user, admin = self.user(), self.user("moderator"), self.user(), self.user("admin")
        path = f"/api/servers/{self.sid}/members/{target.user['id']}/timeout"
        self.assertEqual(online_user.req("POST", path, {"minutes": 5})[0], 403)
        self.assertEqual(mod.req("POST", path, {"minutes": -1})[0], 400)
        self.assertEqual(mod.req("POST", path, {"minutes": 5})[0], 200)
        s, d, _ = self.say(target, "can I talk?")
        self.assertEqual(s, 403)
        self.assertIn("timed out", d["error"])
        self.assertEqual(mod.req("POST", f"/api/servers/{self.sid}/members/{admin.user['id']}/timeout", {"minutes": 5})[0], 403)
        self.assertEqual(mod.req("POST", f"/api/servers/{self.sid}/members/{mod.user['id']}/timeout", {"minutes": 5})[0], 403)
        self.assertEqual(mod.req("POST", path, {"minutes": 0})[0], 200)
        self.assertEqual(self.say(target, "back")[0], 201)

    def test_spam_protection(self):
        u = self.user()
        codes = [self.say(u, f"msg {i}")[0] for i in range(8)]
        self.assertEqual(codes[:6], [201] * 6)
        self.assertIn(429, codes[6:])
        v = self.user()
        self.assertEqual(self.say(v, "same")[0], 201)
        self.assertEqual(self.say(v, "same")[0], 429)

    def test_channel_management(self):
        admin, mod = self.user("admin"), self.user("moderator")
        body = {"name": "Test Room", "topic": "t", "minRead": "online", "minPost": "online"}
        self.assertEqual(mod.req("POST", f"/api/servers/{self.sid}/channels", body)[0], 403)
        s, d, _ = admin.req("POST", f"/api/servers/{self.sid}/channels", body)
        self.assertEqual(s, 201)
        self.assertEqual(admin.req("POST", f"/api/servers/{self.sid}/channels", body)[0], 409)
        self.assertEqual(admin.req("POST", f"/api/servers/{self.sid}/channels", {**body, "name": "x"})[0], 400)
        self.assertEqual(admin.req("POST", f"/api/servers/{self.sid}/channels", {**body, "name": "top", "minRead": "owner"})[0], 403)
        self.assertEqual(mod.req("DELETE", f"/api/channels/{d['id']}")[0], 403)
        self.assertEqual(admin.req("DELETE", f"/api/channels/{d['id']}")[0], 204)

    def test_audit_and_diagnostics_access(self):
        online_user, admin, sa, dev = self.user(), self.user("admin"), self.user("super_admin"), self.user("developer")
        p = f"/api/servers/{self.sid}"
        self.assertEqual(online_user.req("GET", p + "/audit")[0], 403)
        self.assertEqual(admin.req("GET", p + "/audit")[0], 403)
        self.assertEqual(sa.req("GET", p + "/audit")[0], 200)
        self.assertEqual(dev.req("GET", p + "/audit")[0], 403)
        self.assertEqual(dev.req("GET", p + "/diagnostics")[0], 200)
        self.assertEqual(admin.req("GET", p + "/diagnostics")[0], 403)
        _, d, _ = sa.req("GET", p + "/audit")
        self.assertNotIn("text", json.dumps(d["entries"]))  # audit log holds no message content

    def test_server_settings(self):
        admin, mod = self.user("admin"), self.user("moderator")
        self.assertEqual(mod.req("PATCH", f"/api/servers/{self.sid}", {"name": "Hacked"})[0], 403)
        self.assertEqual(admin.req("PATCH", f"/api/servers/{self.sid}", {"name": "BCPS Hub", "description": "Updated"})[0], 200)
        self.assertEqual(admin.req("PATCH", f"/api/servers/{self.sid}", {"name": ""})[0], 400)

    def test_profile_bio(self):
        u = self.user()
        self.assertEqual(u.req("PATCH", "/api/me", {"bio": "I like robots"})[0], 200)
        self.assertEqual(u.req("PATCH", "/api/me", {"bio": "x" * 200})[0], 400)
        _, d, _ = u.req("GET", f"/api/servers/{self.sid}/members")
        self.assertEqual(next(m for m in d["members"] if m["id"] == u.user["id"])["bio"], "I like robots")

    def test_wheel_spin(self):
        u = self.user()
        s, d, _ = u.req("POST", f"/api/servers/{self.sid}/wheel")
        self.assertEqual(s, 200)
        self.assertIn("key", d)
        self.assertIn("label", d)
        self.assertIn("until", d)
        # The wheel role should appear on the member
        _, members, _ = u.req("GET", f"/api/servers/{self.sid}/members")
        me = next(m for m in members["members"] if m["id"] == u.user["id"])
        self.assertEqual(me["wheelRole"], d["key"])
        # The primary role should NOT change
        self.assertEqual(me["role"], "online")

    def test_websocket_realtime_and_visibility(self):
        sender, reader, online_user = self.user(), self.user(), self.user()
        low_mod = self.user("low_moderator")
        for cookie, origin, expected in ((None, True, 401), (reader.cookie, False, 403)):
            bad = WSClient(self.port, cookie, origin=origin)
            self.assertEqual(bad.status, expected)
            bad.close()
        r, st, hp = WSClient(self.port, reader.cookie), WSClient(self.port, online_user.cookie), WSClient(self.port, low_mod.cookie)
        for w in (r, st, hp):
            self.assertEqual(w.status, 101)
        try:
            self.say(sender, "live message")
            ev = r.next_event()
            while ev and ev["type"] != "message.new":
                ev = r.next_event()
            self.assertEqual(ev["message"]["text"], "live message")
            self.assertEqual(ev["message"]["user"]["name"], sender.user["name"])
            # restricted channel: low_moderator receives, plain online user must not
            self.say(low_mod, "staff only secret", "staff-lounge")
            seen = []
            for w in (hp, st):
                got = []
                end = time.time() + 1.5
                while time.time() < end:
                    try:
                        e = w.next_event(0.3)
                    except (socket.timeout, TimeoutError):
                        continue
                    if e:
                        got.append(e)
                seen.append(got)
            self.assertTrue(any(e["type"] == "message.new" and e["message"]["text"] == "staff only secret" for e in seen[0]))
            self.assertFalse(any("staff only secret" in json.dumps(e) for e in seen[1]))
        finally:
            for w in (r, st, hp):
                w.close()

    def test_presence_flag(self):
        u = self.user()
        w = WSClient(self.port, u.cookie)
        try:
            time.sleep(0.2)
            _, d, _ = u.req("GET", f"/api/servers/{self.sid}/members")
            self.assertTrue(next(m for m in d["members"] if m["id"] == u.user["id"])["online"])
        finally:
            w.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
