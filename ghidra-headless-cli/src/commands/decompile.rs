//! Decompile a function to C (`ghidra.app.decompiler.flatapi.FlatDecompilerAPI`).

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct DecompileArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    program: String,
    /// Function entry address (hex)
    #[arg(long)]
    address: String,
    /// Decompiler timeout in seconds [default: 0 = library default]
    #[arg(long)]
    timeout_secs: Option<i64>,
}

pub fn run(args: DecompileArgs, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("FlatDecompilerAPI")
            .str("file", args.program)
            .str("address", args.address)
            .opt_int("timeoutSecs", args.timeout_secs)
            .build(),
    )?;

    let name = response
        .get("function")
        .and_then(Json::as_str)
        .unwrap_or("?");
    let address = response.get("address").and_then(Json::as_str).unwrap_or("?");
    log::info!("decompiled {} at {}", name, address);

    // The C source is the primary output: print it to stdout for piping.
    if let Some(text) = response.get("decompilation").and_then(Json::as_str) {
        println!("{}", text);
    }
    Ok(())
}
