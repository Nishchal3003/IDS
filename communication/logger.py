"""
logger.py
---------
Centralised logging configuration for the Intelligent-NIDS
communication module.

Design rationale
----------------
•  A single factory function (get_logger) is the ONLY way any module
   should obtain a logger.  This guarantees:
     – Uniform log format across server, client, and utilities.
     – File + console output controlled from one place.
     – No duplicate handlers when the same logger is requested twice.
•  Log files are stored under  logs/<role>/  so server and client logs
   never overwrite each other even when running on the same machine for
   testing.
•  Log rotation is enabled (5 MB / 3 backups) to prevent unbounded growth
   during long capture sessions.

Usage
-----
    from communication.logger import get_logger
    log = get_logger("server")
    log.info("Server started on port 5000")
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Module-level cache so the same logger is never configured twice
# ---------------------------------------------------------------------------
_loggers: dict[str, logging.Logger] = {}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOGS_DIR: Path     = PROJECT_ROOT / "logs"

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
LOG_FORMAT: str  = (
    "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
)
DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_LEVEL: int      = logging.DEBUG
MAX_BYTES: int          = 5 * 1024 * 1024   # 5 MB
BACKUP_COUNT: int       = 3


def get_logger(
    name: str,
    level: int = DEFAULT_LEVEL,
    log_dir: Optional[Path] = None,
) -> logging.Logger:
    """
    Return a fully configured :class:`logging.Logger` for *name*.

    The logger writes to both:
      • ``stdout``                   – coloured via StreamHandler
      • ``logs/<name>/<name>.log``   – rotating file

    Subsequent calls with the same *name* return the cached instance
    without re-adding handlers.

    Parameters
    ----------
    name:
        Logical component name, e.g. ``"server"``, ``"client"``,
        ``"protocol"``.  Used as both the Python logger name and the
        subdirectory under ``logs/``.
    level:
        Minimum severity to capture. Defaults to ``logging.DEBUG``.
    log_dir:
        Override the log file directory.  Defaults to
        ``<project_root>/logs/<name>/``.

    Returns
    -------
    logging.Logger
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(level)
    # Prevent propagation to the root logger (avoids duplicate output)
    logger.propagate = False

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    # ── Console handler ──────────────────────────────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # ── Rotating file handler ────────────────────────────────────────────
    target_dir: Path = log_dir if log_dir else (LOGS_DIR / name)
    target_dir.mkdir(parents=True, exist_ok=True)
    log_file: Path = target_dir / f"{name}.log"

    file_handler = RotatingFileHandler(
        filename=str(log_file),
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    _loggers[name] = logger
    logger.debug("Logger '%s' initialised → %s", name, log_file)
    return logger
