//! `string` subcommand: substring/regex search over the program's defined
//! strings (no query = list all), point lookup of one string at an address,
//! mutating DefineString at an address, and mutating DeleteString at an
//! address. Wires to 4 separate RPC procedures — one per verb.

use clap::{Args, Subcommand};

use crate::client::Client;
use crate::common::address_set;
use crate::json::{Json, Req};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Substring/regex search over defined strings (--query optional; empty = list all)
    Search(SearchArgs),
    /// Look up the single defined string at an address (returns null if no string there)
    Get(GetArgs),
    /// Define a string at an address (mutating)
    Define(DefineArgs),
    /// Delete the defined string at an address (mutating; bytes preserved)
    Delete(DeleteArgs),
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Substring (or regex with --regex) to match against decoded string values;
    /// empty or omitted means list every defined string in scope
    #[arg(long)]
    pub query: Option<String>,
    /// Treat --query as a regular expression [default: false]
    #[arg(long)]
    pub regex: bool,
    /// Case-insensitive match [default: false]
    #[arg(long)]
    pub ignore_case: bool,
    /// Cap the number of results [default: 0 = unlimited]
    #[arg(long, default_value_t = 0i64)]
    pub limit: i64,
    /// Restrict to a single address
    #[arg(long)]
    pub address: Option<String>,
    /// Restrict to one or more address ranges (START:END, repeatable)
    #[arg(long = "address-set", value_name = "RANGE")]
    pub address_set: Vec<String>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Address to look up
    #[arg(long)]
    pub address: String,
}

#[derive(Args, Debug)]
pub struct DefineArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Address to define the string at
    #[arg(long)]
    pub address: String,
    /// String kind: cstring | string | utf8 | utf16 | unicode | pascal | pascal255
    #[arg(long, value_name = "KIND")]
    pub kind: String,
    /// Length in bytes (required for fixed-length kinds: string, utf8, unicode)
    #[arg(long)]
    pub length: Option<i64>,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Address of the defined string to delete
    #[arg(long)]
    pub address: String,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let req = match &cmd {
        Cmd::Search(a) => {
            let mut b = Req::new("SearchStrings").str("file", a.program.clone());
            b = b
                .opt_str("query", a.query.clone())
                .bool("regex", a.regex)
                .bool("ignoreCase", a.ignore_case)
                .int("limit", a.limit)
                .opt_str("address", a.address.clone());
            match address_set(&a.address_set).map_err(crate::common::log_arg_err)? {
                Some(j) => b.opt_json("addressSet", Some(j)),
                None => b,
            }
            .build()
        }
        Cmd::Get(a) => Req::new("GetString")
            .str("file", a.program.clone())
            .str("address", a.address.clone())
            .build(),
        Cmd::Define(a) => {
            let mut b = Req::new("DefineString")
                .str("file", a.program.clone())
                .str("address", a.address.clone())
                .str("kind", a.kind.clone());
            if let Some(len) = a.length {
                b = b.int("length", len);
            }
            b.build()
        }
        Cmd::Delete(a) => Req::new("DeleteString")
            .str("file", a.program.clone())
            .str("address", a.address.clone())
            .build(),
    };
    let response = client.invoke(req)?;
    print_response(&cmd, &response);
    Ok(())
}

fn print_response(cmd: &Cmd, response: &Json) {
    match cmd {
        Cmd::Search(_) => {
            let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let truncated = response
                .get("truncated")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            log::info!(
                "found {} string(s){}",
                count,
                if truncated {
                    " (truncated by limit)"
                } else {
                    ""
                }
            );
            if let Some(arr) = response.get("strings").and_then(Json::as_array) {
                for s in arr {
                    print_string_match(s);
                }
            }
        }
        Cmd::Get(_) => {
            let addr = response
                .get("address")
                .and_then(Json::as_str)
                .unwrap_or("?");
            match response.get("string") {
                Some(s) if !matches!(s, Json::Null) => {
                    print_string_match(s);
                }
                _ => {
                    log::info!("no defined string at {}", addr);
                }
            }
        }
        Cmd::Define(_) => {
            let addr = response
                .get("address")
                .and_then(Json::as_str)
                .unwrap_or("?");
            let kind = response.get("kind").and_then(Json::as_str).unwrap_or("?");
            let len = response.get("length").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let charset = response
                .get("charset")
                .and_then(Json::as_str)
                .unwrap_or("?");
            log::info!(
                "defined {} string at {} (length={}, charset={})",
                kind,
                addr,
                len,
                charset
            );
        }
        Cmd::Delete(_) => {
            let addr = response
                .get("address")
                .and_then(Json::as_str)
                .unwrap_or("?");
            let dt = response
                .get("dataType")
                .and_then(Json::as_str)
                .unwrap_or("?");
            let len = response.get("length").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            log::info!("deleted string at {} ({} bytes, {})", addr, len, dt);
        }
    }
}

fn print_string_match(s: &Json) {
    let addr = s.get("address").and_then(Json::as_str).unwrap_or("?");
    let repr = s
        .get("representation")
        .and_then(Json::as_str)
        .unwrap_or("?");
    let len = s.get("length").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let charset = s.get("charset").and_then(Json::as_str).unwrap_or("?");
    let dt = s.get("dataType").and_then(Json::as_str).unwrap_or("");
    if dt.is_empty() {
        log::info!("  {}  {}  [{} bytes, {}]", addr, repr, len, charset);
    } else {
        log::info!("  {}  {}  [{} bytes, {}, {}]", addr, repr, len, charset, dt);
    }
}
