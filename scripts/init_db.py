import argparse
import logging
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.config import load_config
from src.logging_setup import setup_logging
from src.mock_db import init_db


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Initialize and seed the mock SQLite database for agent evaluations."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force recreate tables and re-seed sample users even if database exists.",
    )
    args = parser.parse_args()

    config = load_config()
    setup_logging(log_level="INFO")
    logger = logging.getLogger("init_db")

    logger.info(f"Target database path: {config.db_path}")
    logger.info(f"Re-create forced: {args.force}")

    try:
        init_db(db_path=config.db_path, force_recreate=args.force)
        print(f"[SUCCESS] Database initialized successfully at: {config.db_path}")
    except Exception as exc:
        logger.critical(f"Failed to initialize database: {exc}", exc_info=True)
        print(f"[ERROR] Database initialization failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
