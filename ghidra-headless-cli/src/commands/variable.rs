//! Function variable commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::common::Source;
use crate::json::Req;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Add a stack variable to a function
    AddStack {
        /// Target program project path
        #[arg(long)]
        program: String,
        /// Function entry address (hex)
        #[arg(long)]
        address: String,
        /// Stack frame offset [default: 0]
        #[arg(long)]
        stack_offset: Option<i64>,
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
        #[arg(long)]
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
        #[arg(long)]
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
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Variable name
        #[arg(long)]
        name: String,
    },
    /// Rename a variable in a function
    SetName {
        #[arg(long)]
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
        #[arg(long)]
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
    /// Set the comment on a variable
    SetComment {
        #[arg(long)]
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
                .str("program", program)
                .str("address", address)
                .opt_int("stackOffset", stack_offset)
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
                .str("program", program)
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
                .str("program", program)
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
                .str("program", program)
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
                .str("program", program)
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
                .str("program", program)
                .str("address", address)
                .str("name", name)
                .str("dataType", data_type)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::SetComment {
            program,
            address,
            name,
            comment,
        } => client.run_simple(
            Req::new("SetVariableCommentCmd")
                .str("program", program)
                .str("address", address)
                .str("name", name)
                .str("comment", comment)
                .build(),
        ),
    }
}
