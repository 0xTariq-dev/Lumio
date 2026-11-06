from __future__ import annotations

import json
import logging
from datetime import datetime, timezone


class SafeJSONFormatter(logging.Formatter):
    """Emit an allow-listed set of fields; never serialize request or exception text."""

    _allowed_fields = (
        "scan_id",
        "operation",
        "error_type",
        "active",
        "queued",
        "status_code",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }
        for field in self._allowed_fields:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("veridict.worker")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(SafeJSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
