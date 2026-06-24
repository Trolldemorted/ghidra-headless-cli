//! Listing subcommand: dump the GUI Listings-window view for an address range.
//!
//! Wires to the `Listings` RPC procedure. Mirrors `analysis.rs`'s use of
//! `--address` + `--address-set START[:END]` via the shared `common` helpers.
//!
//! Default output is one grep-friendly line per code unit:
//!
//!   <address>  [<label>]  <bytes>  <mnemonic> <representation>
//!
//! `--json` switches to compact JSON (the raw RPC response) so the caller can
//! pipe to `jq` or compare against fixtures.

use clap::Args;

use crate::client::Client;
use crate::common;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct Cmd {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,

    /// Single address (hex). Mutually exclusive with --address-set.
    #[arg(long)]
    pub address: Option<String>,

    /// Address range START[:END] (colon-separated end is inclusive).
    /// Mutually exclusive with --address; may be specified at most once.
    /// Example: `--address-set 0x401000:0x401050` or just `--address-set 0x401000`.
    #[arg(long = "address-set", value_name = "START[:END]")]
    pub address_set: Vec<String>,

    /// Include raw instruction/data bytes (hex) [default: true]
    #[arg(long, default_value_t = true)]
    pub bytes: bool,

    /// Emit the raw RPC JSON response instead of formatted text [default: false]
    #[arg(long)]
    pub json: bool,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    // Exactly one of --address / --address-set is required. The two new checks
    // below reject the "both" and "address-set twice" cases; require_address_or_set
    // already rejects the "neither" case. The server accepts an addressSet
    // array because RpcContext.addressSet does, but the CLI deliberately limits
    // to a single entry — multi-range reads would be confusing in a Listings
    // dump (one range at a time, like the GUI's Listings window).
    common::require_address_or_set(&cmd.address, &cmd.address_set).map_err(common::log_arg_err)?;

    if cmd.address.is_some() && !cmd.address_set.is_empty() {
        return Err(common::log_arg_err(
            "--address and --address-set are mutually exclusive; pick one".to_string(),
        ));
    }
    if cmd.address_set.len() > 1 {
        return Err(common::log_arg_err(
            "--address-set may be specified at most once; use --address-set START:END for one range"
                .to_string()));
    }

    let set = common::address_set(&cmd.address_set).map_err(common::log_arg_err)?;

    let response = client.invoke(
        Req::new("Listings")
            .str("file", &cmd.program)
            .opt_str("address", cmd.address)
            .opt_json("addressSet", set)
            .bool("bytes", cmd.bytes)
            .build(),
    )?;

    if cmd.json {
        // Compact JSON — pipes cleanly to `jq`. Custom Json Display impl
        // serializes without whitespace.
        println!("{}", response);
        return Ok(());
    }

    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    log::info!("{} unit(s)", count);

    if let Some(units) = response.get("units").and_then(Json::as_array) {
        for u in units {
            print_unit(u);
        }
    }
    Ok(())
}

/// Print one line for a unit object (instruction or data row).
///
/// Column layout, left-to-right (single-space separated; columns are
/// minimum-width but expand if a value is longer — e.g. a 15-byte x86
/// instruction is 30 hex chars and widens the bytes column):
///
///   <address>  <label-or-empty>  <bytes-or-empty>  [<mnemonic>] <representation>
///
/// For Data rows the mnemonic column is omitted and the data's type is
/// implicit in the representation (e.g. `"Hello, world!"` makes
/// `type:"char[14]"` redundant on screen; the JSON still carries it).
fn print_unit(u: &Json) {
    let kind = u.get("kind").and_then(Json::as_str).unwrap_or("?");
    let address = u.get("address").and_then(Json::as_str).unwrap_or("");
    let label = u.get("label").and_then(Json::as_str).unwrap_or("");
    let bytes = u.get("bytes").and_then(Json::as_str).unwrap_or("");
    let repr = u.get("representation").and_then(Json::as_str).unwrap_or("");

    let line = match kind {
        "instruction" => {
            let mnemonic = u.get("mnemonic").and_then(Json::as_str).unwrap_or("");
            // 8-byte instructions (16 hex chars) are the common case; widen
            // the bytes column to that minimum so mnemonics line up.
            format!(
                "{:<10} {:<24} {:<16} {:<8} {}",
                address, label, bytes, mnemonic, repr
            )
        }
        "data" => {
            // Data rows have no mnemonic — representation carries the type's
            // rendered value (e.g. `"Hello, world!"` for char[N]). Skip the
            // mnemonic column to keep one line per row.
            format!("{:<10} {:<24} {:<16} {}", address, label, bytes, repr)
        }
        // Unknown / future kind — render as data plus a [kind] tag so the
        // row is never silently dropped. Not expected from the current
        // server; defensive only.
        _ => format!(
            "{:<10} {:<24} {:<16} [{}] {}",
            address, label, bytes, kind, repr
        ),
    };
    println!("{}", line);
}
