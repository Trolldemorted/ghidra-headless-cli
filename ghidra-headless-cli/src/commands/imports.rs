//! Imports subcommand: list external symbols this program imports from its
//! linked libraries. Wires to the `GetImports` RPC procedure.

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct Cmd {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Restrict to function imports only (skip external data) [default: all]
    #[arg(long, value_name = "KIND", default_value = "all")]
    pub r#type: String,
    /// Cap the total number of entries across all libraries [default: 0 = unlimited]
    #[arg(long)]
    pub limit: Option<i64>,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("GetImports")
            .str("file", cmd.program)
            .str("type", cmd.r#type)
            .opt_int("limit", cmd.limit)
            .build(),
    )?;
    print_imports(&response);
    Ok(())
}

fn print_imports(response: &Json) {
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let lib_count = response.get("libraryCount").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response.get("truncated").and_then(Json::as_bool).unwrap_or(false);
    let tail = if truncated { " (truncated by limit)" } else { "" };
    log::info!(
        "found {} import(s) across {} librar{y}{tail}",
        count,
        lib_count,
        y = if lib_count == 1 { "y" } else { "ies" }
    );
    if let Some(libs) = response.get("libraries").and_then(Json::as_array) {
        for lib in libs {
            let name = lib.get("name").and_then(Json::as_str).unwrap_or("?");
            let c = lib.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            println!("  {} ({})", name, c);
            if let Some(entries) = lib.get("entries").and_then(Json::as_array) {
                for e in entries {
                    let n = e.get("name").and_then(Json::as_str).unwrap_or("?");
                    let a = e.get("address").and_then(Json::as_str).unwrap_or("?");
                    let is_fn = e.get("isFunction").and_then(Json::as_bool).unwrap_or(false);
                    let src = e.get("source").and_then(Json::as_str).unwrap_or("");
                    let kind = if is_fn { "function" } else { "data" };
                    println!("    {:<28}  {:<18}  {:<8}  {}", n, a, kind, src);
                }
            }
        }
    }
}
