# WICAP Rust Extension (Optional)

This crate provides optional Rust acceleration for hot-path helpers.
The Python code will fall back automatically if this extension is not built.

## Build (Local)

```bash
python3 -m pip install maturin
cd native/wicap_rust
maturin develop --release
```

## Functions

- `mac_bytes_to_str(bytes) -> str`
- `xxh64_hex(bytes) -> str`

## Integration

`nexus/utils/rust_ext.py` will use this module when available.
