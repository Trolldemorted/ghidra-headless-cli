//! Stack-depth-change commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::json::Req;

#[derive(Subcommand, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Cmd {
    /// Set the stack-depth-change override at a call site (bytes)
    ///
    /// Sign convention: `N` is the delta in bytes the decompiler should
    /// add to its tracked stack depth after the call (replaces the
    /// function's default extrapop). Negative values are common — use
    /// them when the decompiler overestimates depth.
    ///
    /// Limitation: the decompiler only applies the override at call
    /// sites with a flow reference to a known target. Indirect calls
    /// (`CALL [reg+off]`, vtable dispatches) are stored but never
    /// honored. The server returns a clear error in that case.
    SetDepthChange {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Stack depth change in bytes (signed). Use the `=` form for
        /// negative values: `--stack-depth-change=-4` [default: 0]
        #[arg(
            long = "stack-depth-change",
            value_name = "BYTES",
            allow_hyphen_values = true,
            default_value_t = 0i64
        )]
        stack_depth_change: i64,
    },
    /// Remove the stack-depth-change override at an address
    RemoveDepthChange {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
    },
    /// Read the stack-depth-change override currently in effect at an
    /// address (null when unset)
    ///
    /// Distinguishes "unset" from "set but ignored" (e.g. an override
    /// on an indirect call site) so scripts can confirm a stored value
    /// is actually being consulted by the decompiler.
    GetDepthChange {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
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
                .str("file", program)
                .str("address", address)
                .int("stackDepthChange", stack_depth_change)
                .build(),
        ),
        Cmd::RemoveDepthChange { program, address } => client.run_simple(
            Req::new("RemoveStackDepthChangeCommand")
                .str("file", program)
                .str("address", address)
                .build(),
        ),
        Cmd::GetDepthChange { program, address } => {
            let response = client.invoke(
                Req::new("GetStackDepthChangeCommand")
                    .str("file", program)
                    .str("address", address)
                    .build(),
            )?;
            let depth = response.get("depthChange");
            match depth {
                Some(crate::json::Json::Null) | None => println!("unset"),
                Some(crate::json::Json::Num(n)) => println!("{}", *n as i64),
                _ => println!("?"),
            }
            Ok(())
        }
    }
}
