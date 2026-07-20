//! Function variable commands (`ghidra.app.cmd.function`).

use clap::Subcommand;
use clap::ValueEnum;

use crate::client::Client;
use crate::common::Source;
use crate::json::Req;

/// Whether `variable add-stack` should create a parameter (the
/// historical Ghidra default when the offset is non-negative) or a
/// function-local. The two paths route through different Ghidra APIs
/// because `AddStackVarCmd` interprets positive offsets as parameter
/// slots in the caller's frame and negative offsets as locals in the
/// function's own frame — the convention the x86 `EBP`/`RBP`-relative
/// frame layout uses. The explicit `--kind` flag lets the caller
/// override the convention when an offset in the local-frame area is
/// positive (rare, but happens with `SUB ESP, 0x34` frames that the
/// Ghidra decompiler has not folded) or when the caller is sure
/// about the intent.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum StackVarKind {
    /// Insert as a formal parameter. Ghidra's `AddStackVarCmd` will
    /// also auto-route to this for non-negative offsets. Matches the
    /// pre-2026-07-20 default; kept for callers that depend on the
    /// parameter-side behavior.
    Param,
    /// Insert as a function-local variable. Routes through
    /// `Function.addLocalVariable(StorageType.STACK, ...)` so the
    /// offset is always interpreted as local-frame-relative
    /// regardless of sign.
    Local,
}

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
        /// Stack frame offset. NEGATIVE for locals (in the function's
        /// own frame), NON-NEGATIVE for parameters (in the caller's
        /// frame) — the x86 `EBP`/`RBP`-relative convention that
        /// Ghidra's `AddStackVarCmd` follows. For locals at positive
        /// offsets in the local frame, pass `--kind local` to bypass
        /// the convention. Use `=` form for negative values:
        /// `--stack-offset=-4` (avoids clap's leading-dash ambiguity).
        #[arg(long, default_value_t = 0i64, allow_hyphen_values = true)]
        stack_offset: i64,
        /// Insert as a `param` (default) or a `local` [default: param]
        ///
        /// `param` mirrors Ghidra's `AddStackVarCmd` behavior (positive
        /// offset → caller-frame parameter slot). `local` always inserts
        /// a function-local via `Function.addLocalVariable`, regardless
        /// of the offset's sign — use this when the decompiler's
        /// synthetics (e.g. `iStack_30`) need a backing local at a
        /// positive offset in the local frame.
        #[arg(long, value_enum, default_value_t = StackVarKind::Param)]
        kind: StackVarKind,
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
            kind,
            name,
            data_type,
            source,
        } => client.run_simple(
            Req::new("AddStackVarCmd")
                .str("file", program)
                .str("address", address)
                .int("stackOffset", stack_offset)
                .str(
                    "kind",
                    match kind {
                        StackVarKind::Param => "param",
                        StackVarKind::Local => "local",
                    },
                )
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
