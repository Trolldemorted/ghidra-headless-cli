//! Disassemble a function to an instruction listing (`Disassemble` procedure).

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct DisassembleArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    program: String,
    /// Function identifier: entry address (e.g. "0x401000") OR exact function
    /// name (e.g. "main"). Address takes precedence when both would match.
    #[arg(long = "function", alias = "address", value_name = "FN_OR_ADDR")]
    address: String,
    /// Include raw instruction bytes [default: true]
    #[arg(long)]
    bytes: Option<bool>,
}

pub fn run(args: DisassembleArgs, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("Disassemble")
            .str("file", args.program)
            .str("address", args.address)
            .opt_bool("bytes", args.bytes)
            .build(),
    )?;

    let name = response
        .get("function")
        .and_then(Json::as_str)
        .unwrap_or("?");
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    log::info!("disassembled {} ({} instructions)", name, count);

    // One instruction per line on stdout: "<address>  <bytes>  <representation>".
    if let Some(instructions) = response.get("instructions").and_then(Json::as_array) {
        for insn in instructions {
            let address = insn.get("address").and_then(Json::as_str).unwrap_or("");
            let bytes = insn.get("bytes").and_then(Json::as_str).unwrap_or("");
            let repr = insn
                .get("representation")
                .and_then(Json::as_str)
                .unwrap_or("");
            println!("{}  {:<16}  {}", address, bytes, repr);
        }
    }
    Ok(())
}
