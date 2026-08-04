//! Function search command (`FindFunction`).
//!
//! Unified replacement for the older `FindFunctionsByName` and
//! `FindFunctionsByTag` server procedures; adds address lookup.
//! --query is the search string (mandatory). --name / --tag / --address
//! are mutually-exclusive scoping flags: when none is given the query
//! is matched against names AND tags AND addresses (the "all" default).

use clap::{Args, ValueEnum};

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct FindArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    program: String,
    /// Search pattern (substring by default; regex with --regex). Required.
    #[arg(long)]
    query: String,
    /// Restrict the search to function names [default: search names + tags + addresses]
    #[arg(long, conflicts_with_all = ["tag", "address"])]
    name: bool,
    /// Restrict the search to function tags [default: search names + tags + addresses]
    #[arg(long, conflicts_with_all = ["name", "address"])]
    tag: bool,
    /// Interpret the query as an address; returns the function at it [default: search names + tags + addresses]
    #[arg(long, conflicts_with_all = ["name", "tag"])]
    address: bool,
    /// Treat the query as a regular expression [default: false]
    #[arg(long)]
    regex: bool,
    /// Match case-insensitively [default: false]
    #[arg(long)]
    ignore_case: bool,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long, default_value_t = 0i64)]
    limit: i64,
    /// Exclude thunk functions from the results [default: false].
    /// Pushed server-side so thunk-heavy programs don't carry thunk
    /// records over the wire just to drop them client-side.
    #[arg(long)]
    no_thunks: bool,
    /// Output format. `text` (default) preserves the historical
    /// `<address>  <name>` shape with a 1-line informational log to
    /// stderr; `json` emits the structured response as-is;
    /// `csv` / `tsv` are header-row-plus-data with stable column order
    /// (`address,name,tag,is_thunk,namespace`); `ndjson` is one record
    /// per line with no envelope, so `jq` can stream large outputs.
    #[arg(long, value_name = "FORMAT", default_value_t = Format::Text)]
    format: Format,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Csv,
    Tsv,
    Ndjson,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Format::Text => "text",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Tsv => "tsv",
            Format::Ndjson => "ndjson",
        };
        f.write_str(s)
    }
}

pub fn run_find(args: FindArgs, client: &Client) -> Result<(), ()> {
    // Resolve the wire `field` from the three mutually-exclusive booleans.
    let field = if args.name {
        "name"
    } else if args.tag {
        "tag"
    } else if args.address {
        "address"
    } else {
        "all"
    };

    let response = client.invoke(
        Req::new("FindFunction")
            .str("file", args.program)
            .str("query", args.query)
            .str("field", field)
            .bool("regex", args.regex)
            .bool("ignoreCase", args.ignore_case)
            .int("limit", args.limit)
            .bool("noThunks", args.no_thunks)
            .build(),
    )?;

    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    log::info!(
        "found {} function(s){}",
        count,
        if truncated {
            " (truncated by limit)"
        } else {
            ""
        }
    );

    let functions: Vec<Json> = response
        .get("functions")
        .and_then(Json::as_array)
        .map(|arr| arr.to_vec())
        .unwrap_or_default();

    match args.format {
        Format::Text => print_text(&functions),
        Format::Json => {
            // Emit the structured response object as-is so the caller
            // sees the full schema (count, truncated, functions[]).
            println!(
                "{}",
                Json::Obj(vec![
                    ("count".to_string(), Json::Num(count as f64)),
                    ("truncated".to_string(), Json::Bool(truncated)),
                    ("functions".to_string(), Json::Arr(functions.clone())),
                ])
            );
        }
        Format::Ndjson => {
            for f in functions {
                println!("{}", f);
            }
        }
        Format::Csv => print_delim(&functions, b',', true),
        Format::Tsv => print_delim(&functions, b'\t', true),
    }
    Ok(())
}

/// Print one `<address>  <name>` line per match (legacy format). Tags
/// are appended in square brackets when present.
fn print_text(functions: &[Json]) {
    for f in functions {
        let address = f.get("address").and_then(Json::as_str).unwrap_or("");
        let name = f.get("name").and_then(Json::as_str).unwrap_or("");
        let tags = f
            .get("tags")
            .and_then(Json::as_array)
            .map(|t| {
                t.iter()
                    .filter_map(Json::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        if tags.is_empty() {
            println!("{}  {}", address, name);
        } else {
            println!("{}  {}  [{}]", address, name, tags);
        }
    }
}

/// Print CSV/TSV. Stable column order:
/// `address,name,tag,is_thunk,namespace`. Empty cells for absent
/// values (never the literal string "null"). Header is emitted when
/// {@code with_header} is true.
fn print_delim(functions: &[Json], delim: u8, with_header: bool) {
    let mut out = std::io::stdout().lock();
    use std::io::Write;
    if with_header {
        let _ = out.write_all(b"address");
        let _ = out.write_all(std::slice::from_ref(&delim));
        let _ = out.write_all(b"name");
        let _ = out.write_all(std::slice::from_ref(&delim));
        let _ = out.write_all(b"tag");
        let _ = out.write_all(std::slice::from_ref(&delim));
        let _ = out.write_all(b"is_thunk");
        let _ = out.write_all(std::slice::from_ref(&delim));
        let _ = out.write_all(b"namespace\n");
    }
    for f in functions {
        let cols = [
            f.get("address").and_then(Json::as_str).unwrap_or(""),
            f.get("name").and_then(Json::as_str).unwrap_or(""),
            f.get("tag").and_then(Json::as_str).unwrap_or(""),
            if f.get("isThunk").and_then(Json::as_bool).unwrap_or(false) {
                "true"
            } else {
                "false"
            },
            f.get("namespace").and_then(Json::as_str).unwrap_or(""),
        ];
        for (i, c) in cols.iter().enumerate() {
            if i > 0 {
                let _ = out.write_all(std::slice::from_ref(&delim));
            }
            if delim == b',' {
                let _ = write!(out, "{}", csv_escape(c));
            } else {
                let _ = write!(out, "{}", tsv_escape(c));
            }
        }
        let _ = out.write_all(b"\n");
    }
}

/// CSV quoting (RFC 4180-ish): quote when the field contains the
/// delimiter, a quote, a CR, or an LF. Quotes are doubled.
fn csv_escape(s: &str) -> String {
    let needs_quote = s.bytes().any(|b| matches!(b, b',' | b'"' | b'\r' | b'\n'));
    if !needs_quote {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// TSV escaping: replace literal tabs / newlines / carriage returns
/// with safe placeholders so the row stays single-line and
/// un-ambiguous. TSV has no standard escaping; this is the
/// convention used by `csv -T` and most data tools.
fn tsv_escape(s: &str) -> String {
    s.replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
