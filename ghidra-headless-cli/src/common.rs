//! Shared CLI value types and request-building helpers used across command groups.

use clap::ValueEnum;

use crate::json::Json;

/// Ghidra symbol source type. Maps to the server's `SourceType` strings.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Source {
    UserDefined,
    Analysis,
    Imported,
    Default,
}

impl Source {
    /// The wire string the server expects.
    pub fn wire(self) -> &'static str {
        match self {
            Source::UserDefined => "USER_DEFINED",
            Source::Analysis => "ANALYSIS",
            Source::Imported => "IMPORTED",
            Source::Default => "DEFAULT",
        }
    }

    /// Convert an optional `--source` flag into an optional wire string.
    pub fn opt(value: Option<Source>) -> Option<String> {
        value.map(|s| s.wire().to_string())
    }
}

/// Build the `addressSet` JSON value from `START[:END]` range strings.
///
/// Each entry becomes `{ "start": ..., "end"?: ... }`. Returns `None` when the
/// list is empty so the field is omitted.
pub fn address_set(ranges: &[String]) -> Result<Option<Json>, String> {
    if ranges.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(ranges.len());
    for raw in ranges {
        let mut fields = Vec::new();
        match raw.split_once(':') {
            Some((start, end)) => {
                if start.is_empty() || end.is_empty() {
                    return Err(format!("invalid range '{}': expected START:END", raw));
                }
                fields.push(("start".to_string(), Json::Str(start.to_string())));
                fields.push(("end".to_string(), Json::Str(end.to_string())));
            }
            None => {
                fields.push(("start".to_string(), Json::Str(raw.to_string())));
            }
        }
        out.push(Json::Obj(fields));
    }
    Ok(Some(Json::Arr(out)))
}

/// Require that a command targeting an address set received at least one of
/// `--address` or `--address-set`.
pub fn require_address_or_set(
    address: &Option<String>,
    address_set: &[String],
) -> Result<(), String> {
    if address.is_none() && address_set.is_empty() {
        return Err("one of --address or --address-set is required".to_string());
    }
    Ok(())
}

/// Parse a numeric CLI value that may be decimal (`16`, `232`) or hex with
/// a `0x` / `0X` prefix (`0xe8`, `0X0E8`). Returns an error message naming
/// the field on failure (so callers can wrap with `log_arg_err` for the
/// standard CLI error format). Accepts an optional leading `+` / `-` for
/// the decimal case; hex is unsigned (negative hex is nonsensical for
/// the byte-length and address-offset fields this is used for).
pub fn parse_int_dec_or_hex(field: &str, raw: &str) -> Result<i64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(format!("--{}: empty value", field));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // `i64::from_str_radix` requires no prefix — we stripped it.
        // Don't allow a stray sign on hex; it's almost always a typo
        // (e.g. `-0x10` slipping through autocomplete).
        i64::from_str_radix(hex, 16)
            .map_err(|e| format!("--{}: invalid hex '{}': {}", field, raw, e))
    } else {
        s.parse::<i64>()
            .map_err(|e| format!("--{}: invalid number '{}': {}", field, raw, e))
    }
}

/// Parse a `--parameter` value of the form `[NAME=]DATATYPE` into a JSON object
/// `{ "name"?: ..., "dataType": ... }`.
pub fn parse_parameter(raw: &str) -> Result<Json, String> {
    let mut fields = Vec::new();
    let (name, data_type) = match raw.split_once('=') {
        Some((name, dt)) => (Some(name.trim()), dt.trim()),
        None => (None, raw.trim()),
    };
    if data_type.is_empty() {
        return Err(format!("invalid parameter '{}': data type is empty", raw));
    }
    if let Some(name) = name.filter(|n| !n.is_empty()) {
        fields.push(("name".to_string(), Json::Str(name.to_string())));
    }
    fields.push(("dataType".to_string(), Json::Str(data_type.to_string())));
    Ok(Json::Obj(fields))
}

/// Encode bytes as standard (RFC 4648) base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18 & 0x3f) as usize] as char);
        out.push(TABLE[(n >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Log a client-side argument error so it can be passed to `Result::map_err`,
/// yielding the crate's unit error type.
pub fn log_arg_err(message: String) {
    log::error!("{}", message);
}

/// Build the `parameters` JSON array from `--parameter` values, or `None`.
pub fn parameters(params: &[String]) -> Result<Option<Json>, String> {
    if params.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(params.len());
    for p in params {
        out.push(parse_parameter(p)?);
    }
    Ok(Some(Json::Arr(out)))
}
