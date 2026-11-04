//! synapse's canonical JSON — what its goldens and `--emit-ir` comparisons
//! are written in: aeson-pretty with keys sorted (`compare`), a two-space
//! indent and one trailing newline, its strings escaped and its numbers
//! written as aeson writes them.

use serde_json::{Number, Value};

/// `value` in synapse's canonical form: keys sorted by code point, two-space
/// indent, `": "` between a key and its value, `[]` / `{}` when empty, one
/// trailing newline; a string escaped as aeson escapes it (`\"`, `\\`, `\n`,
/// `\r`, `\t`, any other control character `\u00xx`); a number as
/// aeson-pretty writes the one aeson reads from serde_json's text of it.
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write(&mut out, value, 0);
    out.push('\n');
    out
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write(out: &mut String, value: &Value, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => string(out, s),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                indent(out, level + 1);
                write(out, item, level + 1);
            }
            out.push('\n');
            indent(out, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push_str("{\n");
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                indent(out, level + 1);
                string(out, k);
                out.push_str(": ");
                write(out, v, level + 1);
            }
            out.push('\n');
            indent(out, level);
            out.push('}');
        }
    }
}

fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A number as synapse writes it. aeson reads serde_json's text of it as a
/// `Scientific` — its digits, and a power of ten — and aeson-pretty writes
/// that: in exponent form past ±1e19; else, aeson's way, the integer its
/// digits make when the power is not negative, and when it is, Data.Scientific's
/// `Generic` form (fixed for magnitudes in [0.1, 10^7), exponent otherwise).
fn number(n: &Number) -> String {
    let text = n.to_string();
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.as_str()),
    };
    // the coefficient's digits and the power of ten, as aeson parses them
    let (mantissa, exp) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], body[i + 1..].trim_start_matches('+').parse::<i64>().unwrap_or(0)),
        None => (body, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut coefficient: String = format!("{int_part}{frac_part}");
    let power = exp - frac_part.len() as i64;
    let trimmed = coefficient.trim_start_matches('0').to_string();
    coefficient = if trimmed.is_empty() { "0".into() } else { trimmed };
    // Data.Scientific's toDecimalDigits: the digits without trailing zeros,
    // and e with value = 0.d1d2… × 10^e
    let (digits, e) = if coefficient == "0" {
        ("0".to_string(), 0i64)
    } else {
        let e = coefficient.len() as i64 + power;
        (coefficient.trim_end_matches('0').to_string(), e)
    };
    let sign = if negative && coefficient != "0" { "-" } else { "" };
    let past_1e19 = digits != "0" && (e > 20 || (e == 20 && digits != "1"));
    let formatted = if past_1e19 {
        exponent_form(&digits, e)
    } else if power >= 0 && power <= 1024 {
        let mut s = coefficient.clone();
        if coefficient != "0" {
            for _ in 0..power {
                s.push('0');
            }
        }
        s
    } else if e < 0 || e > 7 {
        exponent_form(&digits, e)
    } else {
        fixed_form(&digits, e)
    };
    format!("{sign}{formatted}")
}

/// Data.Scientific's exponent form: `d.ddde<e-1>`, `d.0e<e-1>` for one digit.
fn exponent_form(digits: &str, e: i64) -> String {
    if digits == "0" {
        return "0.0e0".into();
    }
    let (first, rest) = digits.split_at(1);
    if rest.is_empty() {
        format!("{first}.0e{}", e - 1)
    } else {
        format!("{first}.{rest}e{}", e - 1)
    }
}

/// Data.Scientific's fixed form, for 0 ≤ e ≤ 7.
fn fixed_form(digits: &str, e: i64) -> String {
    if e <= 0 {
        let zeros = "0".repeat((-e) as usize);
        return format!("0.{zeros}{digits}");
    }
    let e = e as usize;
    if digits.len() <= e {
        format!("{digits}{}.0", "0".repeat(e - digits.len()))
    } else {
        format!("{}.{}", &digits[..e], &digits[e..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(text: &str) -> String {
        number(&serde_json::from_str::<Number>(text).unwrap())
    }

    #[test]
    fn numbers_as_aeson_pretty_writes_them() {
        assert_eq!(n("0"), "0");
        assert_eq!(n("42"), "42");
        assert_eq!(n("-7"), "-7");
        assert_eq!(n("1.0"), "1.0");
        assert_eq!(n("1.5"), "1.5");
        assert_eq!(n("0.5"), "0.5");
        assert_eq!(n("0.05"), "5.0e-2");
        assert_eq!(n("0.0"), "0.0");
        assert_eq!(n("1234567.5"), "1234567.5");
        assert_eq!(n("12345678.5"), "1.23456785e7");
        assert_eq!(n("9223372036854775807"), "9223372036854775807");
        assert_eq!(n("18446744073709551615"), "1.8446744073709551615e19");
        assert_eq!(n("1e20"), "1.0e20");
        assert_eq!(n("1e16"), "10000000000000000");
        assert_eq!(n("-0.25"), "-0.25");
    }
}
