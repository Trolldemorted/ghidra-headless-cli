//! Function lifecycle and signature commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::commands::{decompile, tag};
use crate::common::{self, Source};
use crate::json::Req;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum UpdateType {
    DynamicStorageFormalParams,
    DynamicStorageAllParams,
    CustomStorage,
}

impl UpdateType {
    fn wire(self) -> &'static str {
        match self {
            UpdateType::DynamicStorageFormalParams => "DYNAMIC_STORAGE_FORMAL_PARAMS",
            UpdateType::DynamicStorageAllParams => "DYNAMIC_STORAGE_ALL_PARAMS",
            UpdateType::CustomStorage => "CUSTOM_STORAGE",
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a function at an address
    Create {
        /// Target program project path
        #[arg(long)]
        program: String,
        /// Entry point address (hex)
        #[arg(long)]
        address: String,
        /// Function name
        #[arg(long)]
        name: Option<String>,
        /// Symbol source type
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Create functions across an address set
    CreateMultiple {
        #[arg(long)]
        program: String,
        /// Single entry point address (hex)
        #[arg(long)]
        address: Option<String>,
        /// Address range START[:END] (repeatable)
        #[arg(long)]
        address_set: Vec<String>,
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Create a thunk function
    CreateThunk {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Thunked function address; omit to auto-detect
        #[arg(long)]
        referenced_function_address: Option<String>,
        /// Check existing function when auto-detecting
        #[arg(long)]
        check_existing: Option<bool>,
    },
    /// Create an external function in a library
    CreateExternal {
        #[arg(long)]
        program: String,
        /// External library name
        #[arg(long)]
        library: String,
        #[arg(long)]
        name: String,
        /// Optional memory address to bind
        #[arg(long)]
        address: Option<String>,
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Create a FunctionDefinition data type from a function
    CreateDefinition {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
    },
    /// Delete the function at an address
    Delete {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
    },
    /// Rename the function at an address
    SetName {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        name: String,
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Set a function's return data type
    SetReturnType {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Data type name, e.g. "int", "void *"
        #[arg(long)]
        data_type: String,
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Apply a C-style signature to a function
    ApplySignature {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// C signature, e.g. "int foo(char *s, int n)"
        #[arg(long)]
        signature: String,
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Update convention, return type and parameters in one shot
    Update {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Parameter storage handling
        #[arg(long, value_enum)]
        update_type: Option<UpdateType>,
        /// Calling convention, e.g. "__stdcall"
        #[arg(long)]
        calling_convention: Option<String>,
        /// Return data type name
        #[arg(long)]
        return_type: Option<String>,
        /// Parameter as [NAME=]DATATYPE (repeatable)
        #[arg(long)]
        parameter: Vec<String>,
        #[arg(long, value_enum)]
        source: Option<Source>,
        /// Override conflicting storage
        #[arg(long)]
        force: Option<bool>,
    },
    /// Toggle varargs on a function
    SetVarargs {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Whether the function has varargs
        #[arg(long)]
        has_var_args: Option<bool>,
    },
    /// Set a function's stack purge size
    SetPurge {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        /// Purge size in bytes
        #[arg(long)]
        purge: Option<i64>,
    },
    /// Set a function's repeatable comment
    SetRepeatableComment {
        #[arg(long)]
        program: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        comment: String,
    },
    /// Decompile a function to C
    Decompile(decompile::DecompileArgs),
    /// Function tag operations
    Tag {
        #[command(subcommand)]
        cmd: tag::Cmd,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::Create {
            program,
            address,
            name,
            source,
        } => client.run_simple(
            Req::new("CreateFunctionCmd")
                .str("program", program)
                .str("address", address)
                .opt_str("name", name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::CreateMultiple {
            program,
            address,
            address_set,
            source,
        } => {
            common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
            let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("CreateMultipleFunctionsCmd")
                    .str("program", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .opt_str("source", Source::opt(source))
                    .build(),
            )
        }
        Cmd::CreateThunk {
            program,
            address,
            referenced_function_address,
            check_existing,
        } => client.run_simple(
            Req::new("CreateThunkFunctionCmd")
                .str("program", program)
                .str("address", address)
                .opt_str("referencedFunctionAddress", referenced_function_address)
                .opt_bool("checkExisting", check_existing)
                .build(),
        ),
        Cmd::CreateExternal {
            program,
            library,
            name,
            address,
            source,
        } => client.run_simple(
            Req::new("CreateExternalFunctionCmd")
                .str("program", program)
                .str("library", library)
                .str("name", name)
                .opt_str("address", address)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::CreateDefinition { program, address } => client.run_simple(
            Req::new("CreateFunctionDefinitionCmd")
                .str("program", program)
                .str("address", address)
                .build(),
        ),
        Cmd::Delete { program, address } => client.run_simple(
            Req::new("DeleteFunctionCmd")
                .str("program", program)
                .str("address", address)
                .build(),
        ),
        Cmd::SetName {
            program,
            address,
            name,
            source,
        } => client.run_simple(
            Req::new("SetFunctionNameCmd")
                .str("program", program)
                .str("address", address)
                .str("name", name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::SetReturnType {
            program,
            address,
            data_type,
            source,
        } => client.run_simple(
            Req::new("SetReturnDataTypeCmd")
                .str("program", program)
                .str("address", address)
                .str("dataType", data_type)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::ApplySignature {
            program,
            address,
            signature,
            source,
        } => client.run_simple(
            Req::new("ApplyFunctionSignatureCmd")
                .str("program", program)
                .str("address", address)
                .str("signature", signature)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::Update {
            program,
            address,
            update_type,
            calling_convention,
            return_type,
            parameter,
            source,
            force,
        } => {
            let params = common::parameters(&parameter).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("UpdateFunctionCommand")
                    .str("program", program)
                    .str("address", address)
                    .opt_str("updateType", update_type.map(|u| u.wire().to_string()))
                    .opt_str("callingConvention", calling_convention)
                    .opt_str("returnType", return_type)
                    .opt_json("parameters", params)
                    .opt_str("source", Source::opt(source))
                    .opt_bool("force", force)
                    .build(),
            )
        }
        Cmd::SetVarargs {
            program,
            address,
            has_var_args,
        } => client.run_simple(
            Req::new("SetFunctionVarArgsCommand")
                .str("program", program)
                .str("address", address)
                .opt_bool("hasVarArgs", has_var_args)
                .build(),
        ),
        Cmd::SetPurge {
            program,
            address,
            purge,
        } => client.run_simple(
            Req::new("SetFunctionPurgeCommand")
                .str("program", program)
                .str("address", address)
                .opt_int("purge", purge)
                .build(),
        ),
        Cmd::SetRepeatableComment {
            program,
            address,
            comment,
        } => client.run_simple(
            Req::new("SetFunctionRepeatableCommentCmd")
                .str("program", program)
                .str("address", address)
                .str("comment", comment)
                .build(),
        ),
        Cmd::Decompile(args) => decompile::run(args, client),
        Cmd::Tag { cmd } => tag::run(cmd, client),
    }
}
