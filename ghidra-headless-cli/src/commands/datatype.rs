//! Function data-type apply/capture commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::common::{self, Source};
use crate::json::Req;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Apply function-definition data types to matching symbols in the set
    ApplyFunction {
        /// Target program project path
        #[arg(long)]
        program: String,
        /// Single entry point address (hex)
        #[arg(long)]
        address: Option<String>,
        /// Address range START[:END] (repeatable)
        #[arg(long)]
        address_set: Vec<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
        /// Create bookmarks for applied types [default: true]
        #[arg(long)]
        create_bookmarks: Option<bool>,
        /// Always replace existing signatures [default: false]
        #[arg(long)]
        always_replace: Option<bool>,
    },
    /// Capture function signatures in the set into the program's DTM
    CaptureFunction {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        address_set: Vec<String>,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::ApplyFunction {
            program,
            address,
            address_set,
            source,
            create_bookmarks,
            always_replace,
        } => {
            common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
            let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("ApplyFunctionDataTypesCmd")
                    .str("program", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .opt_str("source", Source::opt(source))
                    .opt_bool("createBookmarks", create_bookmarks)
                    .opt_bool("alwaysReplace", always_replace)
                    .build(),
            )
        }
        Cmd::CaptureFunction {
            program,
            address,
            address_set,
        } => {
            common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
            let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("CaptureFunctionDataTypesCmd")
                    .str("program", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .build(),
            )
        }
    }
}
