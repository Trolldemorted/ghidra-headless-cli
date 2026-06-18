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

use client::Client;

#[derive(Parser, Debug)]
#[command(
    name = "ghidra-headless-cli",
    about = "Client for the Ghidra headless RPC server",
    version
)]
struct Cli {
    /// RPC server address as host:port
    #[arg(short = 'H', long, global = true, default_value = "127.0.0.1:18000")]
    host: String,

    /// Increase logging verbosity (-v debug, -vv trace with raw ndjson)
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Function create/delete/signature operations
    Function {
        #[command(subcommand)]
        cmd: commands::function::Cmd,
    },
    /// Function tag operations
    Tag {
        #[command(subcommand)]
        cmd: commands::tag::Cmd,
    },
    /// Function variable operations
    Variable {
        #[command(subcommand)]
        cmd: commands::variable::Cmd,
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
    /// Function data-type apply/capture operations
    Datatype {
        #[command(subcommand)]
        cmd: commands::datatype::Cmd,
    },
    /// Decompile a function to C
    Decompile(commands::decompile::DecompileArgs),
    /// Project-level program operations (import, analyze)
    Program {
        #[command(subcommand)]
        cmd: commands::program::Cmd,
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

    let client = Client { host: cli.host };

    let result = match cli.command {
        Command::Function { cmd } => commands::function::run(cmd, &client),
        Command::Tag { cmd } => commands::tag::run(cmd, &client),
        Command::Variable { cmd } => commands::variable::run(cmd, &client),
        Command::Stack { cmd } => commands::stack::run(cmd, &client),
        Command::Analysis { cmd } => commands::analysis::run(cmd, &client),
        Command::Datatype { cmd } => commands::datatype::run(cmd, &client),
        Command::Decompile(args) => commands::decompile::run(args, &client),
        Command::Program { cmd } => commands::program::run(cmd, &client),
    };

    if result.is_err() {
        std::process::exit(1);
    }
}
