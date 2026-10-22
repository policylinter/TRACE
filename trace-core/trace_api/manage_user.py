"""Trusted local provisioning: python -m trace_api.manage_user USER --role viewer.

Password is prompted, never accepted as a command-line argument or printed.
Only the default organization can be provisioned at this stage.
"""
import argparse
import getpass
from sqlalchemy import select
from .database import init_db, SessionLocal
from .models import User
from .access import ensure_default_identity
from .access_models import Membership
from .workspace_models import WorkspaceMember
from .platform import audit
from .rbac import hash_password

def main():
    parser = argparse.ArgumentParser(description="Create a TRACE organization member locally")
    parser.add_argument("username")
    parser.add_argument("--role", choices=("viewer", "analyst", "admin"), required=True)
    args = parser.parse_args()
    username = args.username.strip()
    if not username or len(username) > 64:
        parser.error("username must contain 1 to 64 characters")
    password = getpass.getpass("New password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12 or password != confirmation:
        parser.error("passwords must match and contain at least 12 characters")
    init_db()
    with SessionLocal() as db:
        db.info["actor"] = "operator:" + getpass.getuser()
        ensure_default_identity(db)
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            parser.error("user already exists; no existing account was changed")
        user = User(username=username, display_name=username, password_hash=hash_password(password), role="user", is_active=True)
        db.add(user)
        db.flush()
        db.add(Membership(organization_id="default", user_id=user.id, role=args.role, is_active=True))
        db.add(WorkspaceMember(organization_id="default", workspace_id="default", user_id=user.id, role="viewer" if args.role == "viewer" else "analyst", active=True))
        audit(db, "membership.created", str(user.id), "username=" + username + ";role=" + args.role)
        db.commit()
    print("Organization member created. Enable TRACE_AUTH_ENABLED=1 to require login.")

if __name__ == "__main__":
    main()
