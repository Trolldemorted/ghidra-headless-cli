//! Function variable commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::common::Source;
use crate::json::Req;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Add a stack variable to a function
    AddStack {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Function entry address (hex)
        #[arg(long)]
        address: String,
        /// Stack frame offset [default: 0]
        #[arg(long, default_value_t = 0i64)]
        stack_offset: i64,
        /// Variable name [default: auto-generated]
        #[arg(long)]
        name: Option<String>,
        /// Data type name [default: undefined]
        #[arg(long)]
        data_type: Option<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Add a register variable to a function
    AddRegister {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Register name, e.g. "EAX"
        #[arg(long)]
        register: String,
        /// Variable name [default: auto-generated]
        #[arg(long)]
        name: Option<String>,
        /// Data type name [default: undefined]
        #[arg(long)]
        data_type: Option<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Add a memory variable to a function
    AddMemory {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Variable storage address (hex)
        #[arg(long)]
        memory_address: String,
        /// Variable name [default: auto-generated]
        #[arg(long)]
        name: Option<String>,
        /// Data type name [default: undefined]
        #[arg(long)]
        data_type: Option<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Delete a named variable from a function
    Delete {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Variable name
        #[arg(long)]
        name: String,
    },
    /// Rename a variable in a function
    SetName {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        old_name: String,
        #[arg(long)]
        new_name: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Set a variable's data type
    SetType {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Variable name
        #[arg(long)]
        name: String,
        #[arg(long)]
        data_type: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Set the data type of a decompiler-only local (e.g. `puVar1`)
    ///
    /// Unlike `set-type`, which requires a stored database-backed variable
    /// name, this verb types a register/SSA temporary that only exists in
    /// the decompiler view. It mirrors the GUI's Ctrl-L "Retype Variable":
    /// the type is stored as a dynamic-hash varnode override and persists
    /// across decompiles.
    ///
    /// Supply exactly ONE of two ways to identify the target:
    ///
    ///   * `--decompiler-name <NAME>` — exact display name in the
    ///     function's decompiled C output (e.g. `puVar1`, `iVar2`,
    ///     `param_1`). The server decompiles the function and looks the
    ///     name up in `LocalSymbolMap.getNameToSymbolMap()`.
    ///   * `--at <PC>` + `--storage <STORAGE>` — first-use PC (hex)
    ///     and the storage string the decompiler prints (e.g.
    ///     `EAX:4`, `Stack[-0x4]`). Useful when the display name is
    ///     unstable across decompiles.
    ///
    /// Example: type a `puVar1` register temporary in a scheduled-task
    /// handler so the array deref renders as `puVar1->town_index` instead
    /// of `*(byte *)((int)puVar1 + 0x16)`.
    SetDecompilerType {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Function entry-point address (hex)
        #[arg(long)]
        address: String,
        /// Decompiler display name (e.g. "puVar1"). Mutually exclusive
        /// with `--at`/`--storage`.
        #[arg(long, conflicts_with_all = ["at", "storage"])]
        decompiler_name: Option<String>,
        /// First-use PC address (hex). Mutually exclusive with
        /// `--decompiler-name`; must be paired with `--storage`.
        #[arg(long, conflicts_with_all = ["decompiler_name"])]
        at: Option<String>,
        /// Variable storage string as printed by the decompiler
        /// (e.g. "EAX:4", "Stack[-0x4]"). Mutually exclusive with
        /// `--decompiler-name`; must be paired with `--at`.
        #[arg(long, conflicts_with_all = ["decompiler_name"])]
        storage: Option<String>,
        /// Data type name, e.g. "MarketPriceDriftTask *"
        #[arg(long)]
        data_type: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Set the comment on a variable
    SetComment {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Variable name
        #[arg(long)]
        name: String,
        #[arg(long)]
        comment: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::AddStack {
            program,
            address,
            stack_offset,
            name,
            data_type,
            source,
        } => client.run_simple(
            Req::new("AddStackVarCmd")
                .str("file", program)
                .str("address", address)
                .int("stackOffset", stack_offset)
                .opt_str("name", name)
                .opt_str("dataType", data_type)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::AddRegister {
            program,
            address,
            register,
            name,
            data_type,
            source,
        } => client.run_simple(
            Req::new("AddRegisterVarCmd")
                .str("file", program)
                .str("address", address)
                .str("register", register)
                .opt_str("name", name)
                .opt_str("dataType", data_type)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::AddMemory {
            program,
            address,
            memory_address,
            name,
            data_type,
            source,
        } => client.run_simple(
            Req::new("AddMemoryVarCmd")
                .str("file", program)
                .str("memoryAddress", memory_address)
                .str("address", address)
                .opt_str("name", name)
                .opt_str("dataType", data_type)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::Delete {
            program,
            address,
            name,
        } => client.run_simple(
            Req::new("DeleteVariableCmd")
                .str("file", program)
                .str("address", address)
                .str("name", name)
                .build(),
        ),
        Cmd::SetName {
            program,
            address,
            old_name,
            new_name,
            source,
        } => client.run_simple(
            Req::new("SetVariableNameCmd")
                .str("file", program)
                .str("address", address)
                .str("oldName", old_name)
                .str("newName", new_name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::SetType {
            program,
            address,
            name,
            data_type,
            source,
        } => client.run_simple(
            Req::new("SetVariableDataTypeCmd")
                .str("file", program)
                .str("address", address)
                .str("name", name)
                .str("dataType", data_type)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::SetDecompilerType {
            program,
            address,
            decompiler_name,
            at,
            storage,
            data_type,
            source,
        } => {
            // Exactly one of the two identification paths must be present.
            // clap's `conflicts_with_all` rejects the case where
            // `--decompiler-name` is set alongside `--at`/`--storage`, but
            // it does not catch "neither set" or "--at without --storage"
            // (those have no conflict target). Validate here.
            let has_name = decompiler_name.is_some();
            let has_pc_path = at.is_some() && storage.is_some();
            let half_pc =
                (at.is_some() && storage.is_none()) || (at.is_none() && storage.is_some());
            if has_name && has_pc_path {
                log::error!(
                    "--decompiler-name is mutually exclusive with --at/--storage; \
                     supply exactly one"
                );
                return Err(());
            }
            if !has_name && !has_pc_path {
                if half_pc {
                    log::error!("--at and --storage must be supplied together");
                } else {
                    log::error!(
                        "supply exactly one of --decompiler-name, or --at together with --storage"
                    );
                }
                return Err(());
            }
            client.run_simple(
                Req::new("RetypeDecompilerVariable")
                    .str("file", program)
                    .str("address", address)
                    .opt_str("decompilerName", decompiler_name)
                    .opt_str("pc", at)
                    .opt_str("storage", storage)
                    .str("dataType", data_type)
                    .opt_str("source", Source::opt(source))
                    .build(),
            )
        }
        Cmd::SetComment {
            program,
            address,
            name,
            comment,
        } => client.run_simple(
            Req::new("SetVariableCommentCmd")
                .str("file", program)
                .str("address", address)
                .str("name", name)
                .str("comment", comment)
                .build(),
        ),
    }
}
