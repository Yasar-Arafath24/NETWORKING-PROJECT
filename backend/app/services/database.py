import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import DeclarativeBase, sessionmaker


# ---------------------------------------------------------
# PROJECT PATHS & FAILSAFE DISCOVERY
# ---------------------------------------------------------

# database.py is inside backend/app/services/
# Walk up securely to guarantee discovery of the .env file
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"
DATABASE_PATH = PROJECT_ROOT / "netsentry.db"


# ---------------------------------------------------------
# LOAD ENVIRONMENT VARIABLES
# ---------------------------------------------------------

# override=True drops stale DATABASE_URL values cached in terminal processes
if ENV_FILE.exists():
    load_dotenv(dotenv_path=ENV_FILE, override=True)
else:
    load_dotenv(override=True)


# ---------------------------------------------------------
# DATABASE URL CONFIGURATION & AUTO-ROUTING
# ---------------------------------------------------------

def get_database_url() -> str:
    database_variables = (
        "NETSENTRY_DATABASE_URL",
        "SUPABASE_DATABASE_URL",
        "SUPABASE_DB_URL",
        "DATABASE_URL",
    )

    for variable in database_variables:
        value = os.getenv(variable, "").strip().strip('"').strip("'")
        if value:
            # Keep the supplied connection string intact. Connection routing must
            # never synthesize a URL with a placeholder credential or missing host.
            return value

    # Fallback to local file architecture if cloud configs are completely absent
    return f"sqlite:///{DATABASE_PATH.as_posix()}"


DATABASE_URL = get_database_url()


# ---------------------------------------------------------
# SUPABASE POOLER USERNAME NORMALIZATION
# ---------------------------------------------------------

def normalize_supabase_url(database_url: str) -> str:
    if not database_url.startswith(("postgresql://", "postgres://")):
        return database_url

    project_ref = os.getenv("SUPABASE_PROJECT_REF", "sncvzdiebkpljsqwbxjk").strip().strip('"')
    if not project_ref:
        return database_url

    if "pooler.supabase.com" not in database_url:
        return database_url

    try:
        prefix, remainder = database_url.split("://", 1)
        userinfo, separator, host_and_database = remainder.partition("@")

        if not separator:
            return database_url

        # Ensure pooling username format maps exactly to 'postgres.[PROJECT_REF]'
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
            if username == "postgres":
                userinfo = f"postgres.{project_ref}:{password}"

        return f"{prefix}://{userinfo}@{host_and_database}"
    except Exception:
        return database_url


DATABASE_URL = normalize_supabase_url(DATABASE_URL)


# ---------------------------------------------------------
# DATABASE URL SCHEME NORMALIZATION
# ---------------------------------------------------------

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)


# ---------------------------------------------------------
# DATABASE URL VALIDATION
# ---------------------------------------------------------

def validate_database_url(value: str) -> URL:
    try:
        url = make_url(value)
    except (ArgumentError, TypeError, ValueError) as e:
        raise RuntimeError(
            f"Invalid database URL configuration string: {str(e)}. Check your .env parameters."
        ) from None

    if url.drivername.startswith("postgresql"):
        if not url.host:
            raise RuntimeError("PostgreSQL hostname is missing from DATABASE_URL.")
        if not url.username:
            raise RuntimeError("PostgreSQL username is missing from DATABASE_URL.")
        if not url.password:
            raise RuntimeError("PostgreSQL password is missing from DATABASE_URL.")
        if url.port is None:
            raise RuntimeError("PostgreSQL port is missing or unparseable from DATABASE_URL.")
        if not 1 <= url.port <= 65535:
            raise RuntimeError("Invalid PostgreSQL port range provided.")
    elif "sqlite" not in url.drivername:
        raise RuntimeError(f"Unsupported database architecture engine type: {url.drivername}")

    return url


# Fetch configuration layout mappings safely
DATABASE_CONFIG = validate_database_url(DATABASE_URL)


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

engine_options = {}

if "sqlite" in DATABASE_CONFIG.drivername:
    engine_options["connect_args"] = {"check_same_thread": False}
elif DATABASE_CONFIG.drivername.startswith("postgresql"):
    engine_options["pool_pre_ping"] = True
    engine_options["pool_recycle"] = 300


# CRITICAL FIX: Passing raw sanitized string directly into create_engine instead of the 
# configuration object avoids hidden environment resolution loops causing Host Translation crashes.
engine = create_engine(
    DATABASE_URL,
    **engine_options,
)


# ---------------------------------------------------------
# DATABASE SESSION
# ---------------------------------------------------------

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


# ---------------------------------------------------------
# SQLALCHEMY BASE
# ---------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------
# DATABASE DEPENDENCY
# ---------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------
# SAFE DATABASE CONFIGURATION OUTPUT
# ---------------------------------------------------------

print("=" * 55)
print("NetSentry AI - Database Connection Configuration")
print("=" * 55)
print("Database Engine   :", DATABASE_CONFIG.drivername)
print("Database Host     :", DATABASE_CONFIG.host or "Local SQLite Instance")
print("Database Port     :", DATABASE_CONFIG.port or "N/A")
print("Database Name     :", DATABASE_CONFIG.database)
print("Configuration Env :", "Successfully Loaded (.env)" if ENV_FILE.exists() else "Process Environment Default")
print("=" * 55)
