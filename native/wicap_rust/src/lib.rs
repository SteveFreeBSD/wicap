use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::fmt::Write;
use xxhash_rust::xxh64::xxh64;

#[pyfunction]
fn mac_bytes_to_str(data: &Bound<'_, PyBytes>) -> PyResult<String> {
    let bytes = data.as_bytes();
    if bytes.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "mac_bytes_to_str expects 6 bytes",
        ));
    }
    let mut out = String::with_capacity(17);
    for (idx, b) in bytes.iter().enumerate() {
        if idx > 0 {
            out.push(':');
        }
        let _ = write!(&mut out, "{:02x}", b);
    }
    Ok(out)
}

#[pyfunction]
fn xxh64_hex(data: &Bound<'_, PyBytes>) -> PyResult<String> {
    let bytes = data.as_bytes();
    let hash = xxh64(bytes, 0);
    Ok(format!("{:016x}", hash))
}

#[pymodule]
fn wicap_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(mac_bytes_to_str, m)?)?;
    m.add_function(wrap_pyfunction!(xxh64_hex, m)?)?;
    Ok(())
}
