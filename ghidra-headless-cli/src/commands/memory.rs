//! `memory` subcommand: static-memory labels (create / rename / delete /
//! set-primary / list / lookup / get), raw byte reads, and applying a data
//! type at an address. Wires to 9 separate RPC procedures — one per verb.

use clap::{Args, Subcommand};

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a data label at an address
    CreateLabel(CreateLabelArgs),
    /// Rename a label (exact name; --address disambiguates)
    RenameLabel(RenameLabelArgs),
    /// Delete a label (exact name; --address disambiguates)
    DeleteLabel(DeleteLabelArgs),
    /// Promote a label to the primary slot at its address
    SetPrimary(SetPrimaryArgs),
    /// List all data labels (substring match)
    ListLabels(ListLabelsArgs),
    /// Look up symbols by name (substring/regex/case; --address narrows)
    LookupLabel(LookupLabelArgs),
    /// Get the primary label (and all secondary labels) at an address
    GetLabel(GetLabelArgs),
    /// Read bytes starting at an address
    ReadBytes(ReadBytesArgs),
    /// Apply a data type at an address (or address range)
    ApplyType(ApplyTypeArgs),
}

#[derive(Args, Debug)]
pub struct CreateLabelArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Address to label (e.g. 0x401000)
    #[arg(long)]
    pub address: String,
    /// Label name
    #[arg(long)]
    pub name: String,
    /// Source type: USER_DEFINED | IMPORTED | ANALYSIS | AI [default: USER_DEFINED]
    #[arg(long, value_name = "KIND", default_value = "USER_DEFINED")]
    pub source: String,
}

#[derive(Args, Debug)]
pub struct RenameLabelArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Current label name (exact match)
    #[arg(long)]
    pub query: String,
    /// Disambiguate when multiple symbols share the name
    #[arg(long)]
    pub address: Option<String>,
    /// New label name (named `--name` to match `create-label --name`)
    #[arg(long, value_name = "NEW_NAME")]
    pub name: String,
    /// Source type for the rename [default: USER_DEFINED]
    #[arg(long, value_name = "KIND", default_value = "USER_DEFINED")]
    pub source: String,
}

#[derive(Args, Debug)]
pub struct DeleteLabelArgs {
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Label name to delete (exact match)
    #[arg(long)]
    pub query: String,
    /// Disambiguate when multiple symbols share the name
    #[arg(long)]
    pub address: Option<String>,
}

#[derive(Args, Debug)]
pub struct SetPrimaryArgs {
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Label name to promote (exact match)
    #[arg(long)]
    pub query: String,
    /// Address the label lives at
    #[arg(long)]
    pub address: String,
}

#[derive(Args, Debug)]
pub struct ListLabelsArgs {
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Substring to match (case-sensitive unless --ignore-case) [default: empty = all]
    #[arg(long)]
    pub query: Option<String>,
    /// Treat --query as a regex [default: false]
    #[arg(long)]
    pub regex: Option<bool>,
    /// Case-insensitive name match [default: false]
    #[arg(long)]
    pub ignore_case: Option<bool>,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long)]
    pub limit: Option<i64>,
}

#[derive(Args, Debug)]
pub struct LookupLabelArgs {
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Name to search for (substring by default)
    #[arg(long)]
    pub query: String,
    /// Treat --query as a regex [default: false]
    #[arg(long)]
    pub regex: Option<bool>,
    /// Case-insensitive name match [default: false]
    #[arg(long)]
    pub ignore_case: Option<bool>,
    /// Restrict the search to one address
    #[arg(long)]
    pub address: Option<String>,
}

#[derive(Args, Debug)]
pub struct GetLabelArgs {
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Address to inspect
    #[arg(long)]
    pub address: String,
}

#[derive(Args, Debug)]
pub struct ReadBytesArgs {
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Start address
    #[arg(long)]
    pub address: String,
    /// Number of bytes to read [default: 16]
    #[arg(long, default_value = "16")]
    pub length: i64,
    /// Output format: hex | dump [default: hex]
    #[arg(long, value_name = "FMT", default_value = "hex")]
    pub format: String,
}

/// Args for `memory apply-type`. Lays a data type at a single address or
/// across a range; the only `memory` verb that consumes a type definition.
/// Was previously `datatype apply` — moved because it operates on program
/// memory (clears the existing code unit, then `Listing.createData`) rather
/// than on the DTM.
#[derive(Args, Debug)]
pub struct ApplyTypeArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Data type to apply (C-syntax expression or full path; leading '/' stripped)
    #[arg(long = "type")]
    pub type_name: String,
    /// Single address to apply at (hex)
    #[arg(long, conflicts_with = "address_set")]
    pub address: Option<String>,
    /// Address range as START[:END] (repeatable). When given, --address is ignored.
    #[arg(long = "address-set", value_name = "START[:END]")]
    pub address_set: Vec<String>,
    /// Byte length to consume at a single address. Only honored for Dynamic
    /// types (typedefs, strings, FactoryDataType); a mismatch against a
    /// fixed-length type (int, char, struct, ...) is rejected. [default: type's length]
    #[arg(long)]
    pub length: Option<i64>,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let req = match &cmd {
        Cmd::CreateLabel(a) => Req::new("CreateLabel")
            .str("file", a.program.clone())
            .str("address", a.address.clone())
            .str("name", a.name.clone())
            .str("source", a.source.clone())
            .build(),
        Cmd::RenameLabel(a) => Req::new("RenameLabel")
            .str("file", a.program.clone())
            .str("query", a.query.clone())
            .opt_str("address", a.address.clone())
            .str("newName", a.name.clone())
            .str("source", a.source.clone())
            .build(),
        Cmd::DeleteLabel(a) => Req::new("DeleteLabel")
            .str("file", a.program.clone())
            .str("query", a.query.clone())
            .opt_str("address", a.address.clone())
            .build(),
        Cmd::SetPrimary(a) => Req::new("SetPrimary")
            .str("file", a.program.clone())
            .str("query", a.query.clone())
            .str("address", a.address.clone())
            .build(),
        Cmd::ListLabels(a) => Req::new("ListLabels")
            .str("file", a.program.clone())
            .opt_str("query", a.query.clone())
            .opt_bool("regex", a.regex)
            .opt_bool("ignoreCase", a.ignore_case)
            .opt_int("limit", a.limit)
            .build(),
        Cmd::LookupLabel(a) => Req::new("LookupLabel")
            .str("file", a.program.clone())
            .str("query", a.query.clone())
            .opt_bool("regex", a.regex)
            .opt_bool("ignoreCase", a.ignore_case)
            .opt_str("address", a.address.clone())
            .build(),
        Cmd::GetLabel(a) => Req::new("GetLabel")
            .str("file", a.program.clone())
            .str("address", a.address.clone())
            .build(),
        Cmd::ReadBytes(a) => Req::new("ReadBytes")
            .str("file", a.program.clone())
            .str("address", a.address.clone())
            .int("length", a.length)
            .str("format", a.format.clone())
            .build(),
        Cmd::ApplyType(a) => {
            let mut req = Req::new("ApplyDataType")
                .str("file", a.program.clone())
                .str("type", a.type_name.clone())
                .opt_int("length", a.length);
            if !a.address_set.is_empty() {
                let items: Vec<Json> = a
                    .address_set
                    .iter()
                    .map(|s| {
                        let parts: Vec<&str> = s.splitn(2, ':').collect();
                        let start = parts[0].to_string();
                        let end = parts.get(1).map(|e| (*e).to_string());
                        let mut fields = vec![("start".to_string(), Json::Str(start))];
                        if let Some(e) = end {
                            fields.push(("end".to_string(), Json::Str(e)));
                        }
                        Json::Obj(fields)
                    })
                    .collect();
                req = req.opt_json("addressSet", Some(Json::Arr(items)));
                req.build()
            } else {
                req.opt_str("address", a.address.clone()).build()
            }
        }
    };
    let response = client.invoke(req)?;
    print_response(&cmd, &response);
    Ok(())
}

fn print_response(cmd: &Cmd, response: &Json) {
    match cmd {
        Cmd::CreateLabel(_) | Cmd::RenameLabel(_) | Cmd::SetPrimary(_) => {
            if let Some(o) = response.get("name").and_then(Json::as_str) {
                let addr = response.get("address").and_then(Json::as_str).unwrap_or("?");
                let src = response.get("source").and_then(Json::as_str).unwrap_or("?");
                log::info!("label: {} @ {}  ({})", o, addr, src);
            }
        }
        Cmd::DeleteLabel(_) => {
            let d = response.get("deleted").and_then(Json::as_bool).unwrap_or(false);
            let n = response.get("name").and_then(Json::as_str).unwrap_or("?");
            let a = response.get("address").and_then(Json::as_str).unwrap_or("?");
            log::info!("deleted={} {} @ {}", d, n, a);
        }
        Cmd::ListLabels(_) => {
            let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let truncated = response.get("truncated").and_then(Json::as_bool).unwrap_or(false);
            log::info!(
                "found {} label(s){}",
                count,
                if truncated { " (truncated by limit)" } else { "" }
            );
            print_refs(response.get("refs"));
        }
        Cmd::LookupLabel(_) => {
            let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            log::info!("found {} symbol(s)", count);
            print_refs(response.get("refs"));
        }
        Cmd::GetLabel(_) => {
            // Primary label is the deliverable; on stdout so it can be piped
            // (e.g. `ghidra-headless-cli memory get-label ... | xargs ...`).
            // Status (count + secondary labels) goes to stderr.
            let primary = response.get("primary").and_then(Json::as_str);
            let total = response
                .get("all")
                .and_then(Json::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            match primary {
                Some(p) => {
                    println!("{}", p); // data
                    if total > 1 {
                        log::info!(
                            "primary label at {} ({} label(s) total; secondary on stderr below)",
                            response.get("address").and_then(Json::as_str).unwrap_or("?"),
                            total
                        );
                        if let Some(arr) = response.get("all").and_then(Json::as_array) {
                            for entry in arr {
                                let n = entry.get("name").and_then(Json::as_str).unwrap_or("?");
                                let p = entry.get("isPrimary").and_then(Json::as_bool).unwrap_or(false);
                                let tag = if p { " (primary)" } else { "" };
                                log::info!("  {}{}", n, tag);
                            }
                        }
                    }
                }
                None => {
                    log::info!(
                        "no primary label at {}",
                        response.get("address").and_then(Json::as_str).unwrap_or("?")
                    );
                }
            }
        }
        Cmd::ReadBytes(_) => {
            let addr = response.get("address").and_then(Json::as_str).unwrap_or("?");
            let n = response.get("bytesRead").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let req = response.get("length").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            log::info!("read {} of {} byte(s) from {}", n, req, addr);
            if let Some(d) = response.get("data").and_then(Json::as_str) {
                for line in d.split('\n') {
                    println!("{}", line);
                }
            }
        }
        Cmd::ApplyType(_) => {
            let created = response.get("created").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let bytes = response.get("bytes").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            log::info!(
                "applied {} ({} entries, {} bytes)",
                response.get("type").and_then(Json::as_str).unwrap_or("?"),
                created,
                bytes
            );
        }
    }
}

fn print_refs(refs: Option<&Json>) {
    // One entry per line on stdout (the data); the count banner above stays
    // on stderr. Format mirrors the previous human-readable listing so a
    // terminal user still sees aligned output, and a scripter can pipe the
    // lines through awk/cut for the address or name column.
    if let Some(arr) = refs.and_then(Json::as_array) {
        for r in arr {
            let name = r.get("name").and_then(Json::as_str).unwrap_or("?");
            let addr = r.get("address").and_then(Json::as_str).unwrap_or("?");
            let src = r.get("source").and_then(Json::as_str);
            let line = match src {
                Some(s) => format!("{}  {}  ({})", addr, name, s),
                None => format!("{}  {}", addr, name),
            };
            println!("{}", line);
        }
    }
}
