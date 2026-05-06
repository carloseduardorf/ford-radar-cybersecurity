"""
Política RBAC declarativa.

Mapa central de permissões — qualquer mudança fica review-friendly.
Default-deny: ausência no mapa = negar.
"""
from __future__ import annotations

from enum import Enum
from typing import Set

from app.models.user import UserRole


class Permission(str, Enum):
    # Domínio
    READ_COMPETITORS = "competitors:read"
    READ_SCORES = "scores:read"
    READ_ALERTS = "alerts:read"
    INGEST_SPREADSHEET = "spreadsheet:ingest"
    TRIGGER_ML = "ml:trigger"
    # Administração
    MANAGE_USERS = "users:manage"
    READ_AUDIT = "audit:read"
    MANAGE_SETTINGS = "settings:manage"


PERMISSIONS: dict[UserRole, Set[Permission]] = {
    UserRole.user: {
        Permission.READ_COMPETITORS,
        Permission.READ_SCORES,
        Permission.READ_ALERTS,
    },
    UserRole.analyst: {
        Permission.READ_COMPETITORS,
        Permission.READ_SCORES,
        Permission.READ_ALERTS,
        Permission.INGEST_SPREADSHEET,
        Permission.TRIGGER_ML,
    },
    UserRole.admin: {p for p in Permission},  # admin tem tudo
}


def has_permission(role: str, permission: Permission) -> bool:
    try:
        role_enum = UserRole(role)
    except ValueError:
        return False
    return permission in PERMISSIONS.get(role_enum, set())


def require_permission(role: str, permission: Permission) -> None:
    """Levanta PermissionError se o papel não tiver a permissão."""
    if not has_permission(role, permission):
        raise PermissionError(f"role={role} sem permissão {permission.value}")
