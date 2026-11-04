"""Role hierarchy and permission rules. Every check here is enforced server-side."""

from __future__ import annotations

# Lowest -> highest. The order IS the hierarchy.
ROLES = ["student", "normie", "helper", "moderator", "admin",
         "developer", "super_admin", "co_owner", "owner"]
ROLE_LEVEL = {role: i + 1 for i, role in enumerate(ROLES)}

ROLE_INFO = {
    "student":     {"label": "Student",     "badge": "STU", "color": "#9aa4b2"},
    "normie":      {"label": "Normie",      "badge": "NRM", "color": "#4fcf86"},
    "helper":      {"label": "Helper",      "badge": "HLP", "color": "#2fd0d0"},
    "moderator":   {"label": "Moderator",   "badge": "MOD", "color": "#4d8dff"},
    "admin":       {"label": "Admin",       "badge": "ADM", "color": "#ff8a3d"},
    "developer":   {"label": "Developer",   "badge": "DEV", "color": "#b57bff"},
    "super_admin": {"label": "Super Admin", "badge": "SA",  "color": "#ff4d79"},
    "co_owner":    {"label": "Co-Owner",    "badge": "CO",  "color": "#f5a623"},
    "owner":       {"label": "Owner",       "badge": "OWN", "color": "#ffd43b"},
}

_BASE = frozenset({"read", "send", "react", "report"})
_HELPER = _BASE | {"view_reports"}
_MOD = _HELPER | {"resolve_reports", "delete_messages", "timeout_members"}
_ADMIN = _MOD | {"manage_channels", "manage_server", "manage_roles"}
_SUPER = _ADMIN | {"view_audit", "view_diagnostics"}
_CO = _SUPER | {"manage_invites"}

# Permissions are explicit per role (NOT derived from level), so e.g. Developer
# gets diagnostics without automatically receiving moderation or owner powers.
PERMS: dict[str, frozenset[str]] = {
    "student": _BASE,
    "normie": _BASE,
    "helper": frozenset(_HELPER),
    "moderator": frozenset(_MOD),
    "admin": frozenset(_ADMIN),
    "developer": frozenset(_BASE | {"view_diagnostics"}),
    "super_admin": frozenset(_SUPER),
    "co_owner": frozenset(_CO),
    "owner": frozenset(_CO),
}

# Messages allowed per 10 seconds.
MESSAGE_RATE = {"student": 6, "normie": 8, "helper": 8, "moderator": 20, "admin": 20,
                "developer": 12, "super_admin": 20, "co_owner": 20, "owner": 20}


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
