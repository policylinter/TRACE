"""Preserve asset IDs, extension columns, links, indexes and triggers when
replacing the original global external-key uniqueness with workspace scope.
"""
import re
from sqlalchemy import inspect, text


def migrate_asset_identity(engine):
    constraints = inspect(engine).get_unique_constraints("platform_assets")
    old = next((c for c in constraints if c["column_names"] == ["external_key"]), None)
    if old is None:
        return
    if engine.dialect.name == "postgresql":
        if not old.get("name"):
            raise RuntimeError("named asset identity constraint required")
        name = engine.dialect.identifier_preparer.quote(old["name"])
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE platform_assets DROP CONSTRAINT {name}"))
            conn.execute(text("ALTER TABLE platform_assets ADD CONSTRAINT uq_asset_workspace_key UNIQUE (organization_id, workspace_id, external_key)"))
        return
    if engine.dialect.name != "sqlite":
        raise RuntimeError("workspace asset identity migration supports SQLite and PostgreSQL")
    with engine.connect() as conn:
        foreign_keys = conn.exec_driver_sql("PRAGMA foreign_keys").scalar()
        conn.commit()
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.commit()
        try:
            # Explicit BEGIN includes SQLite DDL in the rollback boundary.
            conn.exec_driver_sql("BEGIN IMMEDIATE")
            original = conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='platform_assets'")).scalar_one()
            scoped, count = re.subn(r"UNIQUE\s*\(\s*external_key\s*\)", "UNIQUE (organization_id, workspace_id, external_key)", original, flags=re.I)
            if count != 1:
                raise RuntimeError("unrecognized legacy asset constraint; migration aborted")
            temporary = "platform_assets_workspace_migration"
            scoped, count = re.subn(r"^(CREATE TABLE\s+)(?:[\"`]platform_assets[\"`]|platform_assets)", lambda m: m[1] + temporary, scoped, count=1, flags=re.I)
            if count != 1:
                raise RuntimeError("unrecognized asset table declaration")
            extensions = conn.execute(text("SELECT sql FROM sqlite_master WHERE tbl_name='platform_assets' AND type IN ('index','trigger') AND sql IS NOT NULL")).scalars().all()
            columns = [c["name"] for c in inspect(conn).get_columns("platform_assets")]
            quoted = ", ".join(engine.dialect.identifier_preparer.quote(c) for c in columns)
            before = conn.exec_driver_sql("SELECT count(*) FROM platform_assets").scalar_one()
            conn.exec_driver_sql(scoped)
            conn.exec_driver_sql(f"INSERT INTO {temporary} ({quoted}) SELECT {quoted} FROM platform_assets")
            after = conn.exec_driver_sql(f"SELECT count(*) FROM {temporary}").scalar_one()
            if before != after:
                raise RuntimeError("asset migration row count mismatch")
            conn.exec_driver_sql("DROP TABLE platform_assets")
            conn.exec_driver_sql(f"ALTER TABLE {temporary} RENAME TO platform_assets")
            for sql in extensions:
                conn.exec_driver_sql(sql)
            # Check relevant relationships, without modifying unrelated legacy data.
            for table in ("platform_assets", "platform_asset_links"):
                if conn.exec_driver_sql(f"PRAGMA foreign_key_check({table})").all():
                    raise RuntimeError("invalid asset references; migration rolled back")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.exec_driver_sql(f"PRAGMA foreign_keys={int(bool(foreign_keys))}")
            conn.commit()
