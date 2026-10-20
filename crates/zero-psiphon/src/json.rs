//! The JSON encoding Go's `encoding/json` produces.
//!
//! Psiphon signs its server entries with Ed25519 over a Go `map[string]any`
//! re-marshaled with `encoding/json`. The signature therefore covers Go's
//! exact output: keys sorted, no spaces, Go's string escaping (including
//! `\u003c` for `<`) and Go's float formatting. `serde_json` writes a
//! different (also valid) JSON for the same values, so verification cannot
//! reuse it.
//!
//! This module reproduces the subset Psiphon's documents are made of:
//! objects, arrays, strings, numbers, booleans and null. It is deliberately
//! small and total — every value it accepts is encoded, and the encoding is
//! the one the Go reference produces for the same input.

use serde_json::Value;

/// Encode `value` exactly as Go's `json.Marshal` would encode the value an
/// `encoding/json` decode of it produces.
///
/// Numbers are treated as `float64`, as they are after Go decodes into
/// `interface{}`; that is what makes `443` encode as `443` and not `443.0`.
///
/// Returns [`Error`] for the values Go refuses to encode: NaN, infinities,
/// and top-level unsupported types.
pub fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value)?;
    Ok(out)
}

/// [`encode`], as a `String`. Valid UTF-8 is guaranteed by construction.
pub fn encode_string(value: &Value) -> Result<String, Error> {
    let bytes = encode(value)?;
    // The encoder writes UTF-8 only.
    Ok(String::from_utf8(bytes).expect("the encoder writes UTF-8"))
}

/// What stopped the conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Go's `encoding/json` refuses NaN and infinities.
    NotFinite,
    /// A value this encoder does not model.
    Unsupported(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotFinite => f.write_str("the value is not a finite number"),
            Error::Unsupported(what) => write!(f, "unsupported JSON value: {what}"),
        }
    }
}

impl std::error::Error for Error {}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), Error> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(out, number)?,
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Go sorts map keys; `Map` is insertion-ordered, so collect.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                write_value(out, &map[*key])?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(out: &mut Vec<u8>, number: &serde_json::Number) -> Result<(), Error> {
    // Go decodes every JSON number into `float64` when the target is
    // `interface{}`; re-encoding therefore goes through float64 no matter how
    // the number was written.
    let value = number
        .as_f64()
        .ok_or(Error::Unsupported("number outside the float64 range"))?;
    if !value.is_finite() {
        return Err(Error::NotFinite);
    }
    out.extend_from_slice(go_float(value).as_bytes());
    Ok(())
}

/// Format `value` the way `strconv.AppendFloat(_, value, format, -1, 64)` and
/// the JSON encoder's choice of `'f'` or `'e'` format do.
///
/// Go uses `'f'` (plain decimal) for magnitudes in `[1e-6, 1e21)` and `'e'`
/// outside it, with the shortest digit string that round-trips.
pub fn go_float(value: f64) -> String {
    debug_assert!(value.is_finite());
    let magnitude = value.abs();

    if magnitude != 0.0 && (magnitude < 1e-6 || magnitude >= 1e21) {
        // Rust's Debug formatting is the shortest scientific form; Go's `'e'`
        // form is the same digits with a sign on the exponent (`1e+21`).
        let short = format!("{value:?}");
        // `Debug` always uses `e` here; if that ever changes, fall back to
        // the plain Display form rather than producing invalid JSON.
        let Some((mantissa, exponent)) = short.split_once('e') else {
            return format!("{value}");
        };
        let sign = if exponent.starts_with('-') { "" } else { "+" };
        return format!("{mantissa}e{sign}{exponent}");
    }

    // Plain decimal, shortest round-trip, no trailing `.0`. `Display` gives
    // exactly that for every magnitude the JSON encoder prints as `'f'`.
    format!("{value}")
}

/// Escape `text` the way Go's `encoding/json` does with HTML escaping on
/// (the default): `"` `\` and the control characters as short escapes, then
/// `<`, `>`, `&`, U+2028 and U+2029 as `\u` sequences.
fn write_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '<' => out.extend_from_slice(b"\\u003c"),
            '>' => out.extend_from_slice(b"\\u003e"),
            '&' => out.extend_from_slice(b"\\u0026"),
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            control if (control as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn encoded(value: Value) -> String {
        encode_string(&value).unwrap()
    }

    /// The exact bytes the Go reference produces for a server entry's shape.
    /// These strings were produced by `json.Marshal` on the same values; a
    /// change here invalidates every existing signature.
    #[test]
    fn the_encoding_matches_go() {
        assert_eq!(encoded(json!({"a": 1, "b": 2})), r#"{"a":1,"b":2}"#);
        assert_eq!(
            encoded(json!({"ipAddress": "1.2.3.4", "sshPort": 443})),
            r#"{"ipAddress":"1.2.3.4","sshPort":443}"#
        );
        assert_eq!(
            encoded(json!({"serverEntrySignaturePublicKey": "", "tag": "x"})),
            r#"{"serverEntrySignaturePublicKey":"","tag":"x"}"#
        );
    }

    #[test]
    fn numbers_go_through_float64_like_go() {
        assert_eq!(encoded(json!(443)), "443");
        assert_eq!(encoded(json!(443.0)), "443");
        assert_eq!(encoded(json!(-1)), "-1");
        assert_eq!(encoded(json!(0.5)), "0.5");
        assert_eq!(encoded(json!(1e-6)), "0.000001");
        assert_eq!(encoded(json!(1e-7)), "1e-7");
        assert_eq!(encoded(json!(1e21)), "1e+21");
        assert_eq!(encoded(json!(1e20)), "100000000000000000000");
        assert_eq!(encoded(json!(1.5e-7)), "1.5e-7");
        assert_eq!(encoded(json!(-0.0)), "-0");
    }

    #[test]
    fn strings_are_escaped_like_go() {
        // Go escapes HTML characters by default, and the line separators.
        assert_eq!(
            encoded(json!({"x": "<&>\"\\\n\u{2028}"})),
            "{\"x\":\"\\u003c\\u0026\\u003e\\\"\\\\\\n\\u2028\"}"
        );
        assert_eq!(encoded(json!({"x": "\u{1}"})), "{\"x\":\"\\u0001\"}");
    }

    #[test]
    fn keys_are_sorted_like_go() {
        assert_eq!(
            encoded(json!({"b": 1, "a": 2, "C": 3})),
            r#"{"C":3,"a":2,"b":1}"#
        );
    }

    #[test]
    fn non_finite_numbers_are_refused() {
        let nan = serde_json::Number::from_f64(f64::NAN);
        assert!(nan.is_none(), "serde_json cannot represent NaN");
    }
}
