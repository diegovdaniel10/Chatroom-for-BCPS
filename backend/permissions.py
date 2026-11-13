"""Role hierarchy and permission rules. Every check here is enforced server-side."""

from __future__ import annotations

# Lowest -> highest. The order IS the hierarchy.
ROLES = [
    "offline",        # 1  - read only, cannot send
    "online",         # 2  - basic user (default)
    "normie",          # 3  - basic user, different badge
    "rookie",          # 4  - wheel cosmetic
    "star",            # 5  - wheel cosmetic
    "champion",        # 6  - wheel cosmetic
    "lucky",           # 7  - wheel cosmetic
    "legend",          # 8  - wheel cosmetic
    "vip",             # 9  - wheel
    "mvps",            # 10 - wheel
    "low_moderator",   # 11
    "moderator",       # 12
    "low_admin",       # 13
    "admin",           # 14
    "super_admin",     # 15
    "developer",       # 16
    "co_owner",        # 17
    "owner",           # 18
]
ROLE_LEVEL = {role: i + 1 for i, role in enumerate(ROLES)}

ROLE_INFO = {
    "offline":         {"label": "Offline",        "badge": "OFF", "color": "#6b7280"},
    "online":          {"label": "Online",         "badge": "ON",  "color": "#3ddc97"},
    "normie":          {"label": "Normie",          "badge": "NRM", "color": "#4fcf86"},
    "rookie":          {"label": "Rookie",          "badge": "RKE", "color": "#7dd3fc"},
    "star":            {"label": "Star",            "badge": "STR", "color": "#fbbf24"},
    "champion":        {"label": "Champion",        "badge": "CHP", "color": "#f97316"},
    "lucky":           {"label": "Lucky",            "badge": "LKY", "color": "#a78bfa"},
    "legend":          {"label": "Legend",          "badge": "LGD", "color": "#f43f5e"},
    "vip":             {"label": "VIP",             "badge": "VIP", "color": "#ffd43b"},
    "mvps":            {"label": "MVPS",            "badge": "MVP", "color": "#ff6b9d"},
    "low_moderator":   {"label": "Low Moderator",   "badge": "LM",  "color": "#2fd0d0"},
    "moderator":       {"label": "Moderator",       "badge": "MOD", "color": "#4d8dff"},
    "low_admin":       {"label": "Low Admin",       "badge": "LA",  "color": "#7c9eff"},
    "admin":           {"label": "Admin",           "badge": "ADM", "color": "#ff8a3d"},
    "super_admin":     {"label": "Super Admin",     "badge": "SA",  "color": "#ff4d79"},
    "developer":       {"label": "Developer",       "badge": "DEV", "color": "#b57bff"},
    "co_owner":        {"label": "Co-Owner",        "badge": "CO",  "color": "#f5a623"},
    "owner":           {"label": "Owner",           "badge": "OWN", "color": "#e8b923"},
    # Wheel-only cosmetic roles (not in the hierarchy, no permissions)
    "vip_1day":        {"label": "VIP (1 Day)",       "badge": "VIP", "color": "#ffd43b"},
    "mvps_1day":       {"label": "MVPS (1 Day)",      "badge": "MVP", "color": "#ff6b9d"},
    "vip_forever":     {"label": "VIP Forever",       "badge": "VIP", "color": "#ffd43b"},
    "mvps_forever":    {"label": "MVPS Forever",      "badge": "MVP", "color": "#ff6b9d"},
}

# Role keys that exist only as wheel awards (not in the ROLES hierarchy).
WHEEL_ONLY_KEYS = ["vip_1day", "mvps_1day", "vip_forever", "mvps_forever"]

# --- Permission sets (explicit per role, NOT derived from level) ---
_READ_ONLY = frozenset({"read"})
_BASE = frozenset({"read", "send", "react", "report"})
_LOW_MOD = _BASE | {"view_reports"}
_MOD = _LOW_MOD | {"resolve_reports", "delete_messages", "timeout_members"}
_LOW_ADMIN = _MOD | {"manage_channels"}
_ADMIN = _LOW_ADMIN | {"manage_server", "manage_roles"}
_SUPER = _ADMIN | {"view_audit", "view_diagnostics"}
_CO = _SUPER | {"manage_invites"}

PERMS: dict[str, frozenset[str]] = {
    "offline": _READ_ONLY,
    "online": _BASE,
    "normie": _BASE,
    "rookie": _BASE,
    "star": _BASE,
    "champion": _BASE,
    "lucky": _BASE,
    "legend": _BASE,
    "vip": _BASE,
    "mvps": _BASE,
    "low_moderator": frozenset(_LOW_MOD),
    "moderator": frozenset(_MOD),
    "low_admin": frozenset(_LOW_ADMIN),
    "admin": frozenset(_ADMIN),
    "developer": frozenset(_BASE | {"view_diagnostics"}),
    "super_admin": frozenset(_SUPER),
    "co_owner": frozenset(_CO),
    "owner": frozenset(_CO),
}

# Outcomes obtainable from the spinning wheel (never includes moderation/admin roles).
# duration=0 means forever; duration>0 means the role expires after that many seconds.
# The wheel role is stored separately from the member's primary role and shown as a
# cosmetic badge alongside it.
WHEEL_OUTCOMES = [
    {"key": "rookie",      "label": "Rookie",       "badge": "RKE", "color": "#7dd3fc", "duration": 0},
    {"key": "star",        "label": "Star",         "badge": "STR", "color": "#fbbf24", "duration": 0},
    {"key": "champion",    "label": "Champion",     "badge": "CHP", "color": "#f97316", "duration": 0},
    {"key": "lucky",       "label": "Lucky",        "badge": "LKY", "color": "#a78bfa", "duration": 0},
    {"key": "legend",      "label": "Legend",       "badge": "LGD", "color": "#f43f5e", "duration": 0},
    {"key": "vip_1day",    "label": "VIP (1 Day)",  "badge": "VIP", "color": "#ffd43b", "duration": 86400},
    {"key": "mvps_1day",   "label": "MVPS (1 Day)", "badge": "MVP", "color": "#ff6b9d", "duration": 86400},
    {"key": "vip_forever", "label": "VIP Forever",  "badge": "VIP", "color": "#ffd43b", "duration": 0},
    {"key": "mvps_forever","label": "MVPS Forever", "badge": "MVP", "color": "#ff6b9d", "duration": 0},
]

# Messages allowed per 10 seconds.
MESSAGE_RATE = {
    "offline": 0,
    "online": 6, "normie": 8,
    "rookie": 6, "star": 7, "champion": 7, "lucky": 6, "legend": 8,
    "vip": 10, "mvps": 10,
    "low_moderator": 12, "moderator": 20,
    "low_admin": 20, "admin": 20,
    "developer": 12, "super_admin": 20, "co_owner": 20, "owner": 20,
}


def level(role: str) -> int:
    return ROLE_LEVEL.get(role, 0)


def has_perm(role: str, perm: str) -> bool:
    return perm in PERMS.get(role, frozenset())


def can_assign(actor_role: str, target_role: str, new_role: str, same_user: bool) -> bool:
    """May `actor` change a member currently holding `target_role` to `new_role`?

    Rules: needs manage_roles; never yourself; the target and the new role must both be
    strictly below the actor; Owner can never be assigned (so there is one Owner and it
    can never be demoted by anyone). Co-Owner can therefore only be granted by the Owner.
    """
    if same_user or not has_perm(actor_role, "manage_roles"):
        return False
    if new_role not in ROLE_LEVEL or new_role == "owner" or target_role not in ROLE_LEVEL:
        return False
    actor = level(actor_role)
    return level(target_role) < actor and level(new_role) < actor


def can_moderate(actor_role: str, target_role: str, same_user: bool = False) -> bool:
    """Hierarchy check for acting on another member (timeouts, deleting their messages)."""
    return (not same_user) and level(target_role) < level(actor_role)
