//! Xref subcommand: list references TO a function / symbol / memory address.
//! Wires to the `GetXrefs` RPC procedure.

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct Cmd {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Target spec: function name / symbol name / hex address
    #[arg(long)]
    pub to: String,
    /// How to interpret --to: function | symbol | address
    #[arg(long, value_name = "KIND", default_value = "function")]
    pub r#type: String,
    /// Match the target address exactly [default: true — composite rows on]
    ///
    /// Takes an explicit BOOL, e.g. `--include-offcut false` or
    /// `--include-offcut=false`. The bare `--include-offcut` is an error
    /// (exit 2), not a shorthand for true.
    /// False restricts the result to references landing on the address you
    /// named, suppressing the composite walk (see this command's help) and
    /// dropping Ghidra's `OffsetReference` instances. True (the default)
    /// also reports references that land on a component of an enclosing
    /// composite, each tagged `[composite -> <addr> <field>]`.
    #[arg(long, value_name = "BOOL", default_value_t = true, action = clap::ArgAction::Set)]
    pub include_offcut: bool,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long, default_value_t = 0i64)]
    pub limit: i64,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("GetXrefs")
            .str("file", cmd.program)
            .str("to", cmd.to)
            .str("type", cmd.r#type)
            .bool("includeOffcut", cmd.include_offcut)
            .int("limit", cmd.limit)
            .build(),
    )?;
    print_xrefs(&response);
    Ok(())
}

fn print_xrefs(response: &Json) {
    if let Some(t) = response.get("target").and_then(Json::as_object) {
        let ty = obj_get(t, "type").and_then(Json::as_str).unwrap_or("?");
        let q = obj_get(t, "query").and_then(Json::as_str).unwrap_or("?");
        let a = obj_get(t, "address").and_then(Json::as_str).unwrap_or("?");
        log::info!("target: {} '{}' -> {}", ty, q, a);
    }
    let count = response.get("count").and_then(Json::as_i64).unwrap_or(0);
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    log::info!(
        "found {} xref(s){}",
        count,
        if truncated {
            " (truncated by limit)"
        } else {
            ""
        }
    );
    if let Some(dt) = response.get("containingDataType").and_then(Json::as_str) {
        log::info!(
            "target is covered by a data item of type `{}`; each [composite -> ...] row names the offset it actually points at, which may not be the queried address",
            dt
        );
    }
    if let Some(refs) = response.get("refs").and_then(Json::as_array) {
        for r in refs {
            let from = r.get("fromAddress").and_then(Json::as_str).unwrap_or("?");
            let from_fn = r.get("fromFunction").and_then(Json::as_str);
            let from_fn_entry = r.get("fromFunctionEntry").and_then(Json::as_str);
            let ref_type = r.get("refType").and_then(Json::as_str).unwrap_or("?");
            let op = r.get("opIndex").and_then(Json::as_i64).unwrap_or(-1);
            let is_ext = r.get("isExternal").and_then(Json::as_bool).unwrap_or(false);
            let is_off = r.get("isOffcut").and_then(Json::as_bool).unwrap_or(false);
            let comp = r
                .get("compositeMatch")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            let comp_addr = r.get("componentAddress").and_then(Json::as_str);
            let comp_field = r.get("componentField").and_then(Json::as_str);
            // A composite row is only meaningful with the offset it resolved
            // to: without it every row looks like a hit on the queried
            // address when none may be.
            let mut tags: Vec<String> = Vec::new();
            if let (Some(a), Some(f)) = (comp_addr, comp_field) {
                tags.push(format!("composite -> {} {}", a, f));
            } else if let Some(a) = comp_addr {
                tags.push(format!("composite -> {}", a));
            } else if comp {
                tags.push("composite".to_string());
            }
            if is_ext {
                tags.push("external".to_string());
            }
            if is_off {
                tags.push("offcut".to_string());
            }
            let flags = if tags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", tags.join(", "))
            };
            println!(
                "{}  {}  op={}{}",
                origin(from, from_fn, from_fn_entry),
                ref_type,
                op,
                flags
            );
        }
    }
}

/// Render the "from" address, and the function that contains it.
///
/// A Ghidra symbol name is only the *containing* function, not necessarily
/// something that starts here — a row printed as `0x57bf4d <Foo::Construct>`
/// reads like the ctor starts at that address when it may not. When the row
/// sits inside the function rather than at its entry, show the offset so the
/// distinction is explicit.
fn origin(from: &str, from_fn: Option<&str>, entry: Option<&str>) -> String {
    match (from_fn, entry) {
        (Some(name), Some(e)) if !from.eq_ignore_ascii_case(e) => {
            let off = hex_delta(e, from);
            match off {
                Some(d) => format!("{}+{:#x} <{}>", from, d, name),
                None => format!("{} <{}>", from, name),
            }
        }
        (Some(name), _) => format!("{} <{}>", from, name),
        (None, _) => from.to_string(),
    }
}

/// How far `b` lies above `a`, for two hex address strings.
///
/// `None` when either does not parse or `b` is below `a` (a function whose
/// body has a chunk before its entry point). Unsigned: addresses in the top
/// half of a 64-bit space do not fit an `i64`, and used to be shown as if
/// they were the entry itself.
fn hex_delta(a: &str, b: &str) -> Option<u64> {
    let parse = |s: &str| {
        // Ghidra prints non-default spaces as `space:offset`.
        let offset = s.rsplit(':').next().unwrap_or(s);
        let digits = offset
            .strip_prefix("0x")
            .or_else(|| offset.strip_prefix("0X"))
            .unwrap_or(offset);
        u64::from_str_radix(digits, 16).ok()
    };
    parse(b)?.checked_sub(parse(a)?)
}

/// Look up a key in a `&[(String, Json)]` (the shape of `Json::as_object`).
fn obj_get<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_delta_is_unsigned_and_never_negative() {
        assert_eq!(hex_delta("00401000", "00401010"), Some(0x10));
        assert_eq!(hex_delta("ram:00401000", "ram:00401004"), Some(4));
        assert_eq!(
            hex_delta("ffffffff80000000", "ffffffff80000020"),
            Some(0x20)
        );
        assert_eq!(hex_delta("00401010", "00401000"), None);
        assert_eq!(hex_delta("zz", "00401000"), None);
    }

    #[test]
    fn origin_shows_offset_only_inside_the_function() {
        assert_eq!(
            origin("ffffffff80000020", Some("f"), Some("ffffffff80000000")),
            "ffffffff80000020+0x20 <f>"
        );
        assert_eq!(origin("00401000", Some("f"), Some("00401000")), "00401000 <f>");
        assert_eq!(origin("00400ff0", Some("f"), Some("00401000")), "00400ff0 <f>");
    }
}
