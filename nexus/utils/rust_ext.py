"""Optional Rust acceleration shim for hot-path helpers."""

from __future__ import annotations

import hashlib

try:
    from wicap_rust import mac_bytes_to_str as _mac_bytes_to_str
    from wicap_rust import xxh64_hex as _xxh64_hex
    HAS_RUST_EXT = True
except ImportError:  # pragma: no cover - optional dependency
    _mac_bytes_to_str = None
    _xxh64_hex = None
    HAS_RUST_EXT = False

try:
    import xxhash as _xxhash
except ImportError:  # pragma: no cover - optional dependency
    _xxhash = None


def mac_bytes_to_str(data: bytes) -> str:
    """Format MAC bytes as lowercase hex string with colons."""
    if _mac_bytes_to_str:
        return _mac_bytes_to_str(data)
    return ":".join(f"{b:02x}" for b in data)


def xxh64_hex(data: bytes) -> str:
    """Return 64-bit hash hex string; falls back if Rust ext not available."""
    if _xxh64_hex:
        return _xxh64_hex(data)
    if _xxhash is not None:
        return _xxhash.xxh64(data).hexdigest()
    return hashlib.md5(data).hexdigest()[:16]
