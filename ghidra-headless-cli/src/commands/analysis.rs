//! Analyzer commands over an address or address set (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::common::{self, Source};
use crate::json::Req;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Analyze stack references for functions in the set
    Stack {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Single entry point address (hex)
        #[arg(long)]
        address: Option<String>,
        /// Address range START[:END] (repeatable)
        #[arg(long)]
        address_set: Vec<String>,
        /// Force processing of already-analyzed functions [default: false]
        #[arg(long)]
        force_processing: Option<bool>,
    },
    /// Newer stack-analysis pass over the set
    StackNew {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        address_set: Vec<String>,
        /// Force processing of already-analyzed functions [default: false]
        #[arg(long)]
        force_processing: Option<bool>,
    },
    /// Result-state-based stack analysis over the set
    StackResultState {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        address_set: Vec<String>,
        /// Force processing of already-analyzed functions [default: false]
        #[arg(long)]
        force_processing: Option<bool>,
    },
    /// Compute stack purge for functions in the set
    Purge {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        address_set: Vec<String>,
    },
    /// Identify and commit parameters/return via the decompiler
    DecompilerParamId {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        address_set: Vec<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
        /// Commit identified data types [default: true]
        #[arg(long)]
        commit_data_types: Option<bool>,
        /// Commit a void return when identified [default: true]
        #[arg(long)]
        commit_void_return: Option<bool>,
        /// Decompiler timeout in seconds [default: 60]
        #[arg(long)]
        timeout: Option<i64>,
    },
    /// Recover switch tables for the function at an address
    DecompilerSwitch {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Decompiler timeout in seconds [default: 60]
        #[arg(long)]
        timeout: Option<i64>,
    },
    /// Decompiler-based calling-convention analysis for a function
    DecompilerConvention {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Decompiler timeout in seconds [default: 60]
        #[arg(long)]
        timeout: Option<i64>,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::Stack {
            program,
            address,
            address_set,
            force_processing,
        } => run_set_force(
            client,
            "FunctionStackAnalysisCmd",
            program,
            address,
            address_set,
            force_processing,
        ),
        Cmd::StackNew {
            program,
            address,
            address_set,
            force_processing,
        } => run_set_force(
            client,
            "NewFunctionStackAnalysisCmd",
            program,
            address,
            address_set,
            force_processing,
        ),
        Cmd::StackResultState {
            program,
            address,
            address_set,
            force_processing,
        } => run_set_force(
            client,
            "FunctionResultStateStackAnalysisCmd",
            program,
            address,
            address_set,
            force_processing,
        ),
        Cmd::Purge {
            program,
            address,
            address_set,
        } => {
            common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
            let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("FunctionPurgeAnalysisCmd")
                    .str("file", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .build(),
            )
        }
        Cmd::DecompilerParamId {
            program,
            address,
            address_set,
            source,
            commit_data_types,
            commit_void_return,
            timeout,
        } => {
            common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
            let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("DecompilerParameterIdCmd")
                    .str("file", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .opt_str("source", Source::opt(source))
                    .opt_bool("commitDataTypes", commit_data_types)
                    .opt_bool("commitVoidReturn", commit_void_return)
                    .opt_int("timeout", timeout)
                    .build(),
            )
        }
        Cmd::DecompilerSwitch {
            program,
            address,
            timeout,
        } => client.run_simple(
            Req::new("DecompilerSwitchAnalysisCmd")
                .str("file", program)
                .str("address", address)
                .opt_int("timeout", timeout)
                .build(),
        ),
        Cmd::DecompilerConvention {
            program,
            address,
            timeout,
        } => client.run_simple(
            Req::new("DecompilerParallelConventionAnalysisCmd")
                .str("file", program)
                .str("address", address)
                .opt_int("timeout", timeout)
                .build(),
        ),
    }
}

/// Shared builder for the three stack-analysis procedures that take an
/// address/address-set plus an optional `forceProcessing` flag.
fn run_set_force(
    client: &Client,
    procedure: &str,
    program: String,
    address: Option<String>,
    address_set: Vec<String>,
    force_processing: Option<bool>,
) -> Result<(), ()> {
    common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
    let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
    client.run_simple(
        Req::new(procedure)
            .str("file", program)
            .opt_str("address", address)
            .opt_json("addressSet", set)
            .opt_bool("forceProcessing", force_processing)
            .build(),
    )
}
