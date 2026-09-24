import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys


def setup_logging(
    log_level: str = "INFO",
    log_file: Path | str | None = None,
) -> None:
    numeric_console_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG) 
    for existing_handler in list(root_logger.handlers):
        root_logger.removeHandler(existing_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_console_level)
    console_format = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)

    if log_file is None:
        project_root = Path(__file__).resolve().parent.parent
        target_log_file = project_root / "logs" / "app.log"
    else:
        target_log_file = Path(log_file)

    target_log_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        filename=target_log_file,
        maxBytes=5 * 1024 * 1024,  # 5 Megabytes
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)  
    file_format = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)
