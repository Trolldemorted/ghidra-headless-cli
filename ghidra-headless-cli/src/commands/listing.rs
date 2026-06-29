//! Listing subcommand: dump the GUI Listings-window view for an address range.
//!
//! Wires to the `Listings` RPC procedure. Mirrors `analysis.rs`'s use of
//! `--address` + `--address-set START[:END]` via the shared `common` helpers.
//!
//! Default output is one grep-friendly line per code unit, INCLUDING the
//! undefined byte gaps the GUI shows between defined units:
//!
//!   <address>  [<label>]  <bytes>  <mnemonic> <representation>
//!   <address>  ""         <bytes>  ??                  (undefined row)
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

    /// Address range START[:END] (END is EXCLUSIVE; the byte at END is NOT
    /// included). Mutually exclusive with --address; may be specified at most
    /// once. Example: `--address-set 0x401000:0x401050` covers 80 bytes
    /// (`0x401000..0x40104f`); `--address-set 0x401000:0x401001` is exactly
    /// one byte. Bare `--address-set 0x401000` is also a single byte.
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
        common::log_arg_err(
            "--address and --address-set are mutually exclusive; pick one".to_string(),
        );
        return Err(());
    }
    if cmd.address_set.len() > 1 {
        common::log_arg_err(
            "--address-set may be specified at most once; use --address-set START:END for one range"
                .to_string());
        return Err(());
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

    if let Some(units) = response.get("units").and_then(Json::as_array) {
        for u in units {
            print_unit(u);
        }
    }
    Ok(())
}

/// Print one line for a unit object (instruction, data, or undefined row).
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
///
/// For Undefined rows (gaps in the GUI's Listing view / rows of the Hex
/// view) the mnemonic slot is filled with `??` so the column count
/// matches the data-row layout — keeps grep patterns like
/// `^0x0...004  ??  ` working across the whole dump.
///
/// Composite Data rows (Struct/Union) get one parent row PLUS one row per
/// immediate component (the server emits them as `kind="data"` with
/// `depth >= 1`). Components are indented by `2 * depth` leading spaces to
/// mirror the GUI's expanded-listing view (a vftable's parent row at
/// depth=0; the inherited base struct at depth=1; that base's fields at
/// depth=2). Indentation breaks column alignment within an expanded
/// group, but matches the GUI's own rendering — and grouping is
/// visually obvious from the address + label anyway.
fn print_unit(u: &Json) {
    let kind = u.get("kind").and_then(Json::as_str).unwrap_or("?");
    let address = u.get("address").and_then(Json::as_str).unwrap_or("");
    let label = u.get("label").and_then(Json::as_str).unwrap_or("");
    let bytes = u.get("bytes").and_then(Json::as_str).unwrap_or("");
    let repr = u.get("representation").and_then(Json::as_str).unwrap_or("");
    let depth = u.get("depth").and_then(Json::as_f64).unwrap_or(0.0) as usize;
    let indent = "  ".repeat(depth);

    let line = match kind {
        "instruction" => {
            let mnemonic = u.get("mnemonic").and_then(Json::as_str).unwrap_or("");
            // 8-byte instructions (16 hex chars) are the common case; widen
            // the bytes column to that minimum so mnemonics line up.
            format!(
                "{}{:<10} {:<24} {:<16} {:<8} {}",
                indent, address, label, bytes, mnemonic, repr
            )
        }
        "data" => {
            // Data rows have no mnemonic — representation carries the type's
            // rendered value (e.g. `"Hello, world!"` for char[N]). Skip the
            // mnemonic column to keep one line per row. Components of a
            // composite parent get indented; the parent's own row does not.
            format!(
                "{}{:<10} {:<24} {:<16} {}",
                indent, address, label, bytes, repr
            )
        }
        // Undefined bytes — server emits one row per 16-byte chunk of the
        // gap (matches the GUI Hex view's row width). Render like a data row
        // but with `??` in the mnemonic slot so the column count matches —
        // a 16-byte hex string is 32 chars and will overflow the {<16} width
        // but that's fine (it widens the column for that line, like data rows
        // do for long byte strings). Gap rows are always top-level (depth=0)
        // — they are not nested under any composite.
        "undefined" => {
            format!("{}{:<10} {:<24} {:<16} ??", indent, address, label, bytes)
        }
        // Unknown / future kind — render as data plus a [kind] tag so the
        // row is never silently dropped. Not expected from the current
        // server; defensive only.
        _ => format!(
            "{}{:<10} {:<24} {:<16} [{}] {}",
            indent, address, label, bytes, kind, repr
        ),
    };
    println!("{}", line);
}
