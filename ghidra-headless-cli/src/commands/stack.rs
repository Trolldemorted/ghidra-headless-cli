//! Stack-depth-change commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::json::Req;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Set the stack-depth-change value at an address
    SetDepthChange {
        /// Target program project path
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Stack depth change in bytes
        #[arg(long)]
        stack_depth_change: Option<i64>,
    },
    /// Remove the stack-depth-change value at an address
    RemoveDepthChange {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::SetDepthChange {
            program,
            address,
            stack_depth_change,
        } => client.run_simple(
            Req::new("SetStackDepthChangeCommand")
                .str("program", program)
                .str("address", address)
                .opt_int("stackDepthChange", stack_depth_change)
                .build(),
        ),
        Cmd::RemoveDepthChange { program, address } => client.run_simple(
            Req::new("RemoveStackDepthChangeCommand")
                .str("program", program)
                .str("address", address)
                .build(),
        ),
    }
}
