"""JSON compatibility helpers with optional orjson acceleration."""

from __future__ import annotations

from typing import Any

try:
    import orjson as _orjson
except ImportError:  # pragma: no cover - optional dependency
    _orjson = None

if _orjson:
    def loads(data: Any) -> Any:
        return _orjson.loads(data)

    def dumps(obj: Any, *, sort_keys: bool = False, **_kwargs: Any) -> str:
        option = 0
        if sort_keys:
            option |= _orjson.OPT_SORT_KEYS
        return _orjson.dumps(obj, option=option).decode("utf-8")
else:
    import json as _json

    def loads(data: Any) -> Any:
        return _json.loads(data)

    def dumps(obj: Any, **kwargs: Any) -> str:
        return _json.dumps(obj, **kwargs)
