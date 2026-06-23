//! Export subcommand: list in-program symbols that are external entry
//! points (what this binary exports). Wires to the `GetExports` RPC procedure.

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct Cmd {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Restrict to function exports only (skip labels) [default: all]
    #[arg(long, value_name = "KIND", default_value = "all")]
    pub r#type: String,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long)]
    pub limit: Option<i64>,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("GetExports")
            .str("file", cmd.program)
            .str("type", cmd.r#type)
            .opt_int("limit", cmd.limit)
            .build(),
    )?;
    print_exports(&response);
    Ok(())
}

fn print_exports(response: &Json) {
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    log::info!(
        "found {} export(s){}",
        count,
        if truncated {
            " (truncated by limit)"
        } else {
            ""
        }
    );
    if let Some(refs) = response.get("refs").and_then(Json::as_array) {
        for r in refs {
            let addr = r.get("address").and_then(Json::as_str).unwrap_or("?");
            let name = r.get("name").and_then(Json::as_str).unwrap_or("?");
            let kind = r.get("symbolType").and_then(Json::as_str).unwrap_or("?");
            let is_thunk = r.get("isThunk").and_then(Json::as_bool).unwrap_or(false);
            let flag = if is_thunk { "  [thunk]" } else { "" };
            println!("{}  {:<32}  {}{}", addr, name, kind, flag);
        }
    }
}
