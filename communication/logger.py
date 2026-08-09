"""Centralised rotating-file + console logger factory for Intelligent-NIDS."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

_loggers: dict[str, logging.Logger] = {}
_LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"
_FMT = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")

def get_logger(name: str, level: int = logging.DEBUG,
               log_dir: Optional[Path] = None) -> logging.Logger:
    """Return a cached, configured logger writing to stdout and a rotating file."""
    if name in _loggers:
        return _loggers[name]

    log = logging.getLogger(name)
    log.setLevel(level)
    log.propagate = False

    ch = logging.StreamHandler()
    ch.setLevel(level); ch.setFormatter(_FMT)
    log.addHandler(ch)

    target = (log_dir or (_LOGS_DIR / name))
    target.mkdir(parents=True, exist_ok=True)
    log_file = target / f"{name}.log"
    fh = RotatingFileHandler(str(log_file), maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    fh.setLevel(level); fh.setFormatter(_FMT)
    log.addHandler(fh)

    _loggers[name] = log
    log.debug("Logger '%s' initialised → %s", name, log_file)
    return log
