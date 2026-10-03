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
    /// Include references whose target is an interior (offcut) address, e.g.
    /// &table+0x18 when `table` is an applied struct [default: true]
    ///
    /// Pass false to match the target address exactly, which also suppresses
    /// the `[composite]` walk described in this command's help.
    #[arg(long, default_value_t = true)]
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
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
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
            let op = r.get("opIndex").and_then(Json::as_f64).unwrap_or(-1.0) as i64;
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

/// Byte distance between two hex address strings, if both parse.
fn hex_delta(a: &str, b: &str) -> Option<i64> {
    let pa = i64::from_str_radix(a.trim_start_matches("0x"), 16).ok()?;
    let pb = i64::from_str_radix(b.trim_start_matches("0x"), 16).ok()?;
    Some(pb - pa)
}

/// Look up a key in a `&[(String, Json)]` (the shape of `Json::as_object`).
fn obj_get<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}
