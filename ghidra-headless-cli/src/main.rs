//! Command-line client for the Ghidra TCP ndjson RPC server.
//!
//! Subcommands mirror the server's procedures, grouped by the area they act on.
//! Each invocation sends one ndjson request and prints the result; a failed RPC
//! (transport error or `success:false`) is logged and exits non-zero.

mod client;
mod commands;
mod common;
mod json;

use clap::{Parser, Subcommand};
use log::LevelFilter;
use std::env;

use client::Client;

/// Default RPC host when neither --host nor $GHIDRA_RPC_HOST is set.
const DEFAULT_HOST: &str = "127.0.0.1:18000";

/// Default for clap's --host flag. Honours $GHIDRA_RPC_HOST so a shell can
/// pre-set the target without repeating the address on every invocation;
/// explicit --host always wins over the env var (clap substitutes this value
/// only when the flag was omitted).
fn default_host() -> String {
    env::var("GHIDRA_RPC_HOST")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_HOST.to_string())
}

/// Resolve the optional write-gate password from $GHIDRA_RPC_WRITE_PASSWORD.
/// Returned as `None` when the variable is unset or empty so the Client
/// knows to skip stamping the `password` field on outgoing requests (the
/// server's own env var being unset then accepts the request anyway).
fn write_password() -> Option<String> {
    env::var("GHIDRA_RPC_WRITE_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())
}

#[derive(Parser, Debug)]
#[command(
    name = "ghidra-headless-cli",
    about = "Client for the Ghidra headless RPC server",
    version
)]
struct Cli {
    /// RPC server address as host:port. Resolved in order: explicit flag,
    /// then $GHIDRA_RPC_HOST, then 127.0.0.1:18000.
    #[arg(short = 'H', long, global = true, default_value_t = default_host())]
    host: String,

    /// Increase logging verbosity (-v debug, -vv trace with raw ndjson) [default: info]
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Function create/delete/signature/tag/variable operations,
    /// plus `decompile` and `disassemble` for individual functions
    Function {
        #[command(subcommand)]
        cmd: commands::function::Cmd,
    },
    /// Stack-depth-change operations
    Stack {
        #[command(subcommand)]
        cmd: commands::stack::Cmd,
    },
    /// Analyzer passes over an address or address set
    Analysis {
        #[command(subcommand)]
        cmd: commands::analysis::Cmd,
    },
    /// Project file operations (import, analyze)
    File {
        #[command(subcommand)]
        cmd: commands::file::Cmd,
    },
    /// Comment operations (EOL/PRE/POST/PLATE/REPEATABLE/DECOMPILER)
    Comment {
        #[command(subcommand)]
        cmd: commands::comment::Cmd,
    },
    /// Data-type management: list / show / create / replace / edit / delete
    /// (use `memory apply-type` to lay a type at an address — that verb was
    /// moved here from `datatype apply` because it operates on memory).
    Datatype {
        #[command(subcommand)]
        cmd: commands::datatype::Cmd,
    },
    /// Cross-references: list references TO a function / symbol / address
    Xrefs(commands::xrefs::Cmd),
    /// Callgraph: walk a function's callers/callees to a depth
    Callgraph(commands::callgraph::Cmd),
    /// External import: list libraries this program pulls symbols from
    Import(commands::import::Cmd),
    /// External export: list entry points this program exposes to other modules
    Export(commands::export::Cmd),
    /// Dump the GUI Listings-window view (Instructions + Data) for an address range
    Listing(commands::listing::Cmd),
    /// Static-memory labels (create/rename/delete/set-primary/list/lookup/get),
    /// raw byte reads, and applying a data type at an address (apply-type)
    Memory {
        #[command(subcommand)]
        cmd: commands::memory::Cmd,
    },
    /// Class / namespace lifecycle operations (create-class,
    /// rename-class, delete-class)
    Namespace {
        #[command(subcommand)]
        cmd: commands::namespace::Cmd,
    },
    /// Defined strings: substring/regex search + get-at-address + define + delete
    String {
        #[command(subcommand)]
        cmd: commands::string::Cmd,
    },
}

fn main() {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    simple_logger::SimpleLogger::new()
        .with_level(level)
        .init()
        .expect("failed to initialize logger");

    let client = Client {
        host: cli.host,
        write_password: write_password(),
    };

    let result = match cli.command {
        Command::Function { cmd } => commands::function::run(cmd, &client),
        Command::Stack { cmd } => commands::stack::run(cmd, &client),
        Command::Analysis { cmd } => commands::analysis::run(cmd, &client),
        Command::File { cmd } => commands::file::run(cmd, &client),
        Command::Comment { cmd } => commands::comment::run(cmd, &client),
        Command::Datatype { cmd } => commands::datatype::run(cmd, &client),
        Command::Xrefs(cmd) => commands::xrefs::run(cmd, &client),
        Command::Callgraph(cmd) => commands::callgraph::run(cmd, &client),
        Command::Import(cmd) => commands::import::run(cmd, &client),
        Command::Export(cmd) => commands::export::run(cmd, &client),
        Command::Listing(cmd) => commands::listing::run(cmd, &client),
        Command::Memory { cmd } => commands::memory::run(cmd, &client),
        Command::String { cmd } => commands::string::run(cmd, &client),
        Command::Namespace { cmd } => commands::namespace::run(cmd, &client),
    };

    if result.is_err() {
        std::process::exit(1);
    }
}
