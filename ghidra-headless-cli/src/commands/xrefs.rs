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
    /// Include offcut references (refs whose "from" is mid-instruction) [default: true]
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
    if let Some(refs) = response.get("refs").and_then(Json::as_array) {
        for r in refs {
            let from = r.get("fromAddress").and_then(Json::as_str).unwrap_or("?");
            let from_fn = r.get("fromFunction").and_then(Json::as_str);
            let ref_type = r.get("refType").and_then(Json::as_str).unwrap_or("?");
            let op = r.get("opIndex").and_then(Json::as_f64).unwrap_or(-1.0) as i64;
            let is_ext = r.get("isExternal").and_then(Json::as_bool).unwrap_or(false);
            let is_off = r.get("isOffcut").and_then(Json::as_bool).unwrap_or(false);
            let in_fn = from_fn.map(|n| format!(" <{}>", n)).unwrap_or_default();
            let flags = match (is_ext, is_off) {
                (true, true) => "  [external,offcut]",
                (true, false) => "  [external]",
                (false, true) => "  [offcut]",
                (false, false) => "",
            };
            println!("{}{}  {}  op={}{}", from, in_fn, ref_type, op, flags);
        }
    }
}

/// Look up a key in a `&[(String, Json)]` (the shape of `Json::as_object`).
fn obj_get<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}
