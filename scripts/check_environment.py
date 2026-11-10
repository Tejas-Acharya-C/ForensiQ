"""Validate ForensiQ startup dependencies, configuration, and application import."""

import argparse
import importlib.util
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

REQUIRED_MODULES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "alembic": "alembic",
    "sqlalchemy": "sqlalchemy",
    "pydantic": "pydantic",
    "pydantic-settings": "pydantic_settings",
    "numpy": "numpy",
    "scikit-learn": "sklearn",
    "python-multipart": "multipart",
    "reportlab": "reportlab",
    "python-dateutil": "dateutil",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-initialization",
        action="store_true",
        help="require a missing absolute SQLite database in development mode",
    )
    parser.add_argument(
        "--import-app",
        action="store_true",
        help="import the FastAPI application after database preflight",
    )
    parser.add_argument(
        "--check-migrations",
        action="store_true",
        help="compare the configured database revision with Alembic heads",
    )
    args = parser.parse_args()

    if sys.version_info < (3, 11):
        print(
            "Python 3.11 or newer is required; found "
            + sys.version.split()[0],
            file=sys.stderr,
        )
        return 1

    missing = [
        package
        for package, module in REQUIRED_MODULES.items()
        if importlib.util.find_spec(module) is None
    ]
    if missing:
        print(
            "Missing dependencies in .venv: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    try:
        from app.core.config import get_settings
        from sqlalchemy.engine import make_url

        settings = get_settings()
        database_url = make_url(settings.DATABASE_URL)
    except Exception as exc:
        print(f"Invalid application or database configuration: {exc}", file=sys.stderr)
        return 1

    if database_url.get_backend_name() == "postgresql":
        if importlib.util.find_spec("psycopg") is None:
            print(
                "Missing dependency in .venv: psycopg[binary]",
                file=sys.stderr,
            )
            return 1

    if args.check_initialization:
        if settings.APP_ENV != "development":
            print(
                "Database initialization is allowed only when APP_ENV=development.",
                file=sys.stderr,
            )
            return 1
        if database_url.get_backend_name() != "sqlite":
            print(
                "Explicit initialization supports only a file-backed SQLite database.",
                file=sys.stderr,
            )
            return 1
        database_name = database_url.database
        if not database_name or database_name == ":memory:":
            print(
                "Explicit initialization requires an absolute SQLite file path.",
                file=sys.stderr,
            )
            return 1
        database_path = Path(database_name)
        if not database_path.is_absolute():
            print(
                "Explicit initialization requires an absolute SQLite file path.",
                file=sys.stderr,
            )
            return 1
        if database_path.exists():
            print(
                "The configured SQLite database already exists; initialization "
                "was refused.",
                file=sys.stderr,
            )
            return 1
        if not database_path.parent.is_dir():
            print(
                "The configured SQLite database directory does not exist; "
                "no directory was created.",
                file=sys.stderr,
            )
            return 1

    if args.check_migrations:
        try:
            from alembic.config import Config
            from alembic.runtime.migration import MigrationContext
            from alembic.script import ScriptDirectory

            repository_root = BACKEND_DIR.parent
            alembic_config = Config(str(repository_root / "alembic.ini"))
            migration_scripts = ScriptDirectory.from_config(alembic_config)
            migration_heads = set(migration_scripts.get_heads())
            from app.database.session import engine

            with engine.connect() as connection:
                current_revisions = set(
                    MigrationContext.configure(connection).get_current_heads()
                )
        except Exception as exc:
            print(f"Could not validate Alembic configuration or revision: {exc}", file=sys.stderr)
            return 1

        if not migration_heads:
            print("Alembic migration graph has no heads.", file=sys.stderr)
            return 1
        if current_revisions != migration_heads:
            current_display = ", ".join(sorted(current_revisions)) or "none"
            heads_display = ", ".join(sorted(migration_heads))
            print(
                f"Database revision(s) [{current_display}] do not match Alembic "
                f"head(s) [{heads_display}]. No migration was applied.",
                file=sys.stderr,
            )
            return 1
        print(
            "Database is at Alembic head: "
            + ", ".join(sorted(current_revisions))
            + "."
        )

    if args.import_app:
        import app.main  # noqa: F401

        print("FastAPI application import OK.")
    elif not args.check_migrations:
        print("Required project dependencies and configuration are available.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
