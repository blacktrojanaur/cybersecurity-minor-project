"""
common.logging_utils – Structured JSON logging for all ZTSP modules.

Usage:
    from common.logging_utils import get_logger
    log = get_logger(__name__)
    log.info("event", session_id="sess-001", score=0.72)
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Format log records as newline-delimited JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra kwargs passed via logger.info("msg", key=val)
        for key, val in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                log_obj[key] = val
        if record.exc_info:
            log_obj["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, default=str)


class StructuredLogger(logging.LoggerAdapter):
    """LoggerAdapter that accepts arbitrary keyword arguments and puts them into extra."""

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        std_keys = ("exc_info", "stack_info", "stacklevel", "extra")
        custom_extra = {k: v for k, v in kwargs.items() if k not in std_keys}
        kwargs_clean = {k: v for k, v in kwargs.items() if k in std_keys}
        extra = dict(kwargs_clean.get("extra") or {})
        extra.update(custom_extra)
        kwargs_clean["extra"] = extra
        return msg, kwargs_clean


def get_logger(name: str, level: str = "INFO") -> StructuredLogger:
    """Return a module-level JSON structured logger supporting arbitrary kwargs."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        logger.propagate = False
    return StructuredLogger(logger, {})
