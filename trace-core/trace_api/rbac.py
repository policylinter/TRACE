"""Password hashing and persisted bearer sessions.

Organization membership is resolved by access.py on each request. Session
credentials are stored as SHA-256 digests, expire after eight hours and can be
revoked across processes sharing the database. Passwords use PBKDF2-HMAC-SHA256.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Any

from sqlalchemy.orm import Session

from .config import AUTH_ENABLED, TRACE_ADMIN_PASSWORD, TRACE_ADMIN_USERNAME
from .database import SessionLocal
from .models import User

_ITERATIONS = 120_000



def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, expected = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


def issue_token(username: str) -> str:
    from datetime import datetime, timedelta, timezone
    from .access_models import AuthSession
    token = secrets.token_urlsafe(32)
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
        if user is None:
            raise ValueError("active user not found")
        db.add(AuthSession(token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id,
                           expires_at=datetime.now(timezone.utc) + timedelta(hours=8)))
        db.commit()
    return token


def user_for_token(token: str | None) -> User | None:
    from datetime import datetime, timezone
    from .access_models import AuthSession
    if not token:
        return None
    with SessionLocal() as db:
        session = db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest())
        if session is None or session.revoked:
            return None
        expiry = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
        if expiry <= datetime.now(timezone.utc):
            return None
        user = db.get(User, session.user_id)
        return user if user is not None and user.is_active else None


def revoke_token(token: str) -> None:
    from .access_models import AuthSession
    with SessionLocal() as db:
        session = db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest())
        if session:
            session.revoked = True
            db.commit()


def ensure_bootstrap(db: Session) -> None:
    """Create the first admin account from env vars when auth is enabled."""
    if not AUTH_ENABLED:
        return
    if db.query(User).count() > 0:
        return
    if not (TRACE_ADMIN_USERNAME and TRACE_ADMIN_PASSWORD):
        return
    admin = User(username=TRACE_ADMIN_USERNAME, role="admin", is_active=True)
    admin.display_name = "Administrator"
    admin.password_hash = hash_password(TRACE_ADMIN_PASSWORD)
    db.add(admin)
    db.commit()


def bearer_from_header(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def serialize_user(user: User) -> dict[str, Any]:
    return {
        "username": user.username,
        "displayName": user.display_name or user.username,
        "role": user.role,
        "isActive": bool(user.is_active),
        "createdAt": user.created_at.isoformat().replace("+00:00", "Z") if user.created_at else "",
    }