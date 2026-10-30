
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Store the database in the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATABASE_PATH = PROJECT_ROOT / "netsentry.db"

DATABASE_URL = (
    os.getenv("NETSENTRY_DATABASE_URL")
    or os.getenv("SUPABASE_DATABASE_URL")
    or os.getenv("SUPABASE_DB_URL")
    or os.getenv("DATABASE_URL")
    or f"sqlite:///{DATABASE_PATH.as_posix()}"
)

# Supabase IPv4/IPv6 pooler URLs require the project reference in the
# PostgreSQL username for some regions: postgres.<project-ref>.
if DATABASE_URL.startswith(("postgresql://", "postgres://")):
    project_ref = os.getenv("SUPABASE_PROJECT_REF", "")
    if project_ref and "pooler.supabase.com" in DATABASE_URL:
        prefix, remainder = DATABASE_URL.split("://", 1)
        userinfo, separator, host_and_database = remainder.partition("@")
        if separator and userinfo.startswith("postgres:") and not userinfo.startswith(
            f"postgres.{project_ref}:"
        ):
            DATABASE_URL = (
                f"{prefix}://postgres.{project_ref}:"
                f"{userinfo[len('postgres:'):]}@{host_and_database}"
            )

# Normalize scheme for psycopg2
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

engine_options = {}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
elif DATABASE_URL.startswith("postgresql"):
    engine_options["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL, **engine_options)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
