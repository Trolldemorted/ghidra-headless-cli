//! Function search commands (`FindFunctionsByName` / `FindFunctionsByTag`).

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct FindByNameArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    program: String,
    /// Substring to search for in function names (or a regex with --regex)
    #[arg(long)]
    query: String,
    /// Treat the query as a regular expression [default: false]
    #[arg(long)]
    regex: Option<bool>,
    /// Match case-insensitively [default: false]
    #[arg(long)]
    ignore_case: Option<bool>,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long)]
    limit: Option<i64>,
}

#[derive(Args, Debug)]
pub struct FindByTagArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    program: String,
    /// Exact tag name a function must have (or a regex over tag names with --regex)
    #[arg(long)]
    query: String,
    /// Treat the query as a regular expression [default: false]
    #[arg(long)]
    regex: Option<bool>,
    /// Match case-insensitively [default: false]
    #[arg(long)]
    ignore_case: Option<bool>,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long)]
    limit: Option<i64>,
}

pub fn run_by_name(args: FindByNameArgs, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("FindFunctionsByName")
            .str("file", args.program)
            .str("query", args.query)
            .opt_bool("regex", args.regex)
            .opt_bool("ignoreCase", args.ignore_case)
            .opt_int("limit", args.limit)
            .build(),
    )?;
    print_matches(&response, false);
    Ok(())
}

pub fn run_by_tag(args: FindByTagArgs, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("FindFunctionsByTag")
            .str("file", args.program)
            .str("query", args.query)
            .opt_bool("regex", args.regex)
            .opt_bool("ignoreCase", args.ignore_case)
            .opt_int("limit", args.limit)
            .build(),
    )?;
    print_matches(&response, true);
    Ok(())
}

/// Print one `<address>  <name>` line per match to stdout (appending `[tags]` when
/// `show_tags`), and log the count to stderr.
fn print_matches(response: &Json, show_tags: bool) {
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    log::info!(
        "found {} function(s){}",
        count,
        if truncated { " (truncated by limit)" } else { "" }
    );

    if let Some(functions) = response.get("functions").and_then(Json::as_array) {
        for f in functions {
            let address = f.get("address").and_then(Json::as_str).unwrap_or("");
            let name = f.get("name").and_then(Json::as_str).unwrap_or("");
            if show_tags {
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
                println!("{}  {}  [{}]", address, name, tags);
            } else {
                println!("{}  {}", address, name);
            }
        }
    }
}
