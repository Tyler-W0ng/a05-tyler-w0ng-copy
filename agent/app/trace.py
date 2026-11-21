"""Run-correlated structured trace events for debugging the pipeline."""
import contextvars
import json
import logging
import uuid
from datetime import datetime, timezone

RUN_ID = contextvars.ContextVar("run_id", default="-")
_current_target = "-"


def start_run() -> str:
    value = uuid.uuid4().hex[:12]
    RUN_ID.set(value)
    return value


def set_target(target_id: str):
    global _current_target
    previous = _current_target
    _current_target = target_id
    return previous


def reset_target(token):
    global _current_target
    _current_target = token


def _safe(value):
    if isinstance(value, dict):
        return {str(key): ("<redacted>" if any(word in str(key).lower()
                for word in ("api_key", "password", "secret", "authorization"))
                else _safe(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def event(logger: logging.Logger, name: str, **details):
    payload = {
        "time": datetime.now(timezone.utc).isoformat(),
        "run_id": RUN_ID.get(),
        "target_id": _current_target,
        "event": name,
        **details,
    }
    logger.info("TRACE %s", json.dumps(_safe(payload), ensure_ascii=False, default=str))
