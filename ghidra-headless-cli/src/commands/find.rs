//! Function search command (`FindFunction`).
//!
//! Unified replacement for the older `FindFunctionsByName` and
//! `FindFunctionsByTag` server procedures; adds address lookup.
//! --query is the search string (mandatory). --name / --tag / --address
//! are mutually-exclusive scoping flags: when none is given the query
//! is matched against names AND tags AND addresses (the "all" default).

use clap::Args;

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
            .build(),
    )?;
    print_matches(&response, false);
    Ok(())
}

/// Print one `<address>  <name>` line per match to stdout (appending
/// `[tags]` when the function has any), and log the count to stderr.
fn print_matches(response: &Json, _show_tags_unused: bool) {
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

    if let Some(functions) = response.get("functions").and_then(Json::as_array) {
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
}
