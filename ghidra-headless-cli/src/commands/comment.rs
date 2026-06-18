//! Comment operations: manage EOL / PRE / POST / PLATE / REPEATABLE / DECOMPILER
//! comments at an address (function-level for DECOMPILER).

use clap::Subcommand;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// End-of-line (trailing) comment at an address
    Eol {
        #[command(subcommand)]
        op: Op,
    },
    /// Pre comment (above the line) at an address
    Pre {
        #[command(subcommand)]
        op: Op,
    },
    /// Post comment (below the line) at an address
    Post {
        #[command(subcommand)]
        op: Op,
    },
    /// Plate comment (function header in the listing) at an address
    Plate {
        #[command(subcommand)]
        op: Op,
    },
    /// Repeatable comment at an address
    Repeatable {
        #[command(subcommand)]
        op: Op,
    },
    /// Function-level decompiler comment at an address (resolves to containing function)
    Decompiler {
        #[command(subcommand)]
        op: Op,
    },
}

#[derive(Subcommand, Debug)]
pub enum Op {
    /// Read the comment at the address
    Get {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Address (hex, e.g. 0x401000)
        #[arg(long)]
        address: String,
    },
    /// Set the comment at the address (empty string clears it)
    Set {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Comment text (omit to clear)
        #[arg(long)]
        text: Option<String>,
    },
    /// Append text to the existing comment
    Append {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Text to append
        #[arg(long)]
        text: String,
        /// Glue between existing and new text [default: newline]
        #[arg(long)]
        separator: Option<String>,
    },
    /// Clear the comment at the address
    Clear {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let (procedure, op) = match &cmd {
        Cmd::Eol { op } => ("Eol", op),
        Cmd::Pre { op } => ("Pre", op),
        Cmd::Post { op } => ("Post", op),
        Cmd::Plate { op } => ("Plate", op),
        Cmd::Repeatable { op } => ("Repeatable", op),
        Cmd::Decompiler { op } => ("Decompiler", op),
    };
    let proc_name = |suffix: &str| format!("{}{}", procedure, suffix);
    match op {
        Op::Get { program, address } => invoke_get(client, &proc_name("Get"), program, address),
        Op::Set { program, address, text } => {
            invoke_set(client, &proc_name("Set"), program, address, text.as_deref())
        }
        Op::Append { program, address, text, separator } => invoke_append(
            client,
            &proc_name("Append"),
            program,
            address,
            text,
            separator.as_deref(),
        ),
        Op::Clear { program, address } => {
            invoke_clear(client, &proc_name("Clear"), program, address)
        }
    }
}

fn invoke_get(client: &Client, procedure: &str, program: &str, address: &str) -> Result<(), ()> {
    let response = client.invoke(
        Req::new(procedure)
            .str("file", program)
            .str("address", address)
            .build(),
    )?;
    print_response(procedure, &response, false);
    Ok(())
}

fn invoke_set(client: &Client, procedure: &str, program: &str, address: &str,
        text: Option<&str>) -> Result<(), ()> {
    let response = client.invoke(
        Req::new(procedure)
            .str("file", program)
            .str("address", address)
            .opt_str("text", text.map(str::to_string))
            .build(),
    )?;
    print_response(procedure, &response, true);
    Ok(())
}

fn invoke_append(client: &Client, procedure: &str, program: &str, address: &str,
        text: &str, separator: Option<&str>) -> Result<(), ()> {
    let response = client.invoke(
        Req::new(procedure)
            .str("file", program)
            .str("address", address)
            .str("text", text)
            .opt_str("separator", separator.map(str::to_string))
            .build(),
    )?;
    print_response(procedure, &response, true);
    Ok(())
}

fn invoke_clear(client: &Client, procedure: &str, program: &str, address: &str) -> Result<(), ()> {
    let response = client.invoke(
        Req::new(procedure)
            .str("file", program)
            .str("address", address)
            .build(),
    )?;
    print_response(procedure, &response, true);
    Ok(())
}

/// Print a one-line summary of the response: type / address / function (if any) / comment.
fn print_response(procedure: &str, response: &Json, show_previous: bool) {
    let type_name = response.get("type").and_then(Json::as_str).unwrap_or("?");
    let address = response.get("address").and_then(Json::as_str).unwrap_or("?");
    let comment = response.get("comment").and_then(Json::as_str).unwrap_or("");
    if let Some(function) = response.get("function").and_then(Json::as_str) {
        log::info!("{} {} {}@{} -> {:?}", procedure, type_name, function, address, comment);
    } else {
        log::info!("{} {} {} -> {:?}", procedure, type_name, address, comment);
    }
    println!("{}", comment);
    if show_previous {
        if let Some(prev) = response.get("previous").and_then(Json::as_str) {
            if !prev.is_empty() {
                log::info!("previous: {}", prev);
            }
        }
    }
}