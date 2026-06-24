//! Function lifecycle and signature commands (`ghidra.app.cmd.function`).

use clap::Subcommand;

use crate::client::Client;
use crate::commands::{decompile, disassemble, find, tag, variable};
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
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Entry point address (hex)
        #[arg(long)]
        address: String,
        /// Function name [default: auto-named, e.g. FUN_<address>]
        #[arg(long)]
        name: Option<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Create functions across an address set
    CreateMultiple {
        #[arg(long = "file", value_name = "FILE")]
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
    },
    /// Create a thunk function
    CreateThunk {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Thunked function address [default: auto-detected]
        #[arg(long)]
        referenced_function_address: Option<String>,
        /// Check existing function when auto-detecting [default: false]
        #[arg(long)]
        check_existing: bool,
    },
    /// Create an external function in a library
    CreateExternal {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// External library name
        #[arg(long)]
        library: String,
        #[arg(long)]
        name: String,
        /// Memory address to bind [default: unbound]
        #[arg(long)]
        address: Option<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Create a FunctionDefinition data type from a function
    CreateDefinition {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
    },
    /// Delete the function at an address
    Delete {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
    },
    /// Rename the function at an address
    ///
    /// `--name` is a BARE LEAF only — it must not contain `::` or `/`.
    /// Passing a value like `Foo::Bar` is rejected with an error, because
    /// Ghidra's underlying rename silently mangles such inputs (doubles
    /// the leaf onto itself when the namespace prefix can't be resolved
    /// relative to the function's current namespace). To move a function
    /// into a different namespace, use `function set-namespace` instead.
    SetName {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Bare leaf name (no `::` or `/`)
        #[arg(long)]
        name: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Set a function's return data type
    SetReturnType {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Data type name, e.g. "int", "void *"
        #[arg(long)]
        data_type: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Apply a C-style signature to a function
    ApplySignature {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// C signature, e.g. "int foo(char *s, int n)"
        ///
        /// `__thiscall` carries an IMPLICIT `this` in ECX (RCX on x64)
        /// that this API cannot retype. To type `this`, use
        /// `function set-class-association` (see its `--help`).
        #[arg(long)]
        signature: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Apply function-definition data types to matching symbols in the set
    ApplyDataTypes {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
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
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        create_bookmarks: bool,
        /// Always replace existing signatures [default: false]
        #[arg(long)]
        always_replace: bool,
    },
    /// Capture function signatures in the set into the program's DTM
    CaptureDataTypes {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        address_set: Vec<String>,
    },
    /// Update convention, return type and parameters in one shot
    Update {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Parameter storage handling [default: dynamic-storage-formal-params]
        #[arg(long, value_enum, default_value_t = UpdateType::DynamicStorageFormalParams)]
        update_type: UpdateType,
        /// Calling convention, e.g. "__stdcall" [default: unchanged]
        ///
        /// `__thiscall` carries an IMPLICIT `this` in ECX (RCX on x64)
        /// that this API cannot retype. To type `this`, use
        /// `function set-class-association` (see its `--help`).
        #[arg(long)]
        calling_convention: Option<String>,
        /// Return data type name [default: unchanged]
        #[arg(long)]
        return_type: Option<String>,
        /// Parameter as [NAME=]DATATYPE (repeatable)
        #[arg(long)]
        parameter: Vec<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
        /// Override conflicting storage [default: false]
        #[arg(long)]
        force: bool,
    },
    /// Toggle varargs on a function
    SetVarargs {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Whether the function has varargs. Pass `false` to clear varargs
        /// from an already-varargs function. [default: true, value: true|false]
        #[arg(long, value_name = "BOOL", default_value_t = true, action = clap::ArgAction::Set)]
        has_var_args: bool,
    },
    /// Set a function's stack purge size
    SetPurge {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        /// Purge size in bytes [default: 0]
        #[arg(long, default_value_t = 0i64)]
        purge: i64,
    },
    /// Set a function's repeatable comment
    SetRepeatableComment {
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        comment: String,
    },
    /// Decompile a function to C
    Decompile(decompile::DecompileArgs),
    /// Disassemble a function to an instruction listing
    Disassemble(disassemble::DisassembleArgs),
    /// Search for functions by name, tag, or address
    Find(find::FindArgs),
    /// Function tag operations
    Tag {
        #[command(subcommand)]
        cmd: tag::Cmd,
    },
    /// Function variable operations
    Variable {
        #[command(subcommand)]
        cmd: variable::Cmd,
    },
    /// Associate a function with a class (the CLI equivalent of the GUI's
    /// "Edit → Set Class Association…")
    ///
    /// Associates the function with a class namespace. The decompiler then
    /// types the function's implicit `this` parameter (for `__thiscall` /
    /// MSVC member functions on x86) as a pointer to the DTM type whose
    /// name matches the class. The lookup is name-based: class and struct
    /// are coupled by NAME ONLY.
    ///
    /// IMPORTANT — auto-stub: This edit may auto-create a stub struct in
    /// the program's DTM named after the class (size 0/1, no fields).
    /// This is Ghidra's default behavior when no struct with the class's
    /// name exists — see FunctionDB.createClassStructIfNeeded(). The
    /// auto-stub is triggered by ANY edit to a function with a class
    /// association, not just this command (e.g. changing the calling
    /// convention to `__thiscall` on an already-associated function will
    /// also fire it).
    ///
    /// To prevent the auto-stub, create a struct with the class's name
    /// in the DTM before associating the function:
    ///   datatype create --kind struct --name <ClassName> ...
    ///
    /// To remove an auto-stub later:
    ///   datatype delete --name <ClassName>
    /// The class association itself is unaffected.
    SetClassAssociation {
        /// Target file project path (e.g. /<prog>.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Function entry-point address (hex)
        #[arg(long)]
        address: String,
        /// Full path of the class namespace (e.g. "/Game/OpMarketTrade")
        #[arg(long)]
        class: String,
    },
    /// Move a function into a (possibly different) namespace and rename it
    ///
    /// Unlike `function set-name` (which only renames the leaf), this verb
    /// both changes the parent namespace and renames the leaf in one
    /// transaction. Use it when the desired fully-qualified name lives in a
    /// different namespace than the function's current one (e.g. promoting
    /// `GameScreen::Foo` to `Multiplayer::Foo`).
    ///
    /// Accepts plain namespaces AND classes. For the class-only variant
    /// with auto-stub semantics (where the decompiler types `this` as the
    /// class's struct), use `function set-class-association` instead.
    SetNamespace {
        /// Target file project path (e.g. /<prog>.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Function entry-point address (hex)
        #[arg(long)]
        address: String,
        /// Slash-delimited namespace path (e.g. "/Game/MultiplayerScreen")
        /// [default: / (global namespace)]
        #[arg(long)]
        namespace: Option<String>,
        /// Bare leaf name (no `::` or `/`)
        #[arg(long)]
        name: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
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
                .str("file", program)
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
                    .str("file", program)
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
                .str("file", program)
                .str("address", address)
                .opt_str("referencedFunctionAddress", referenced_function_address)
                .bool("checkExisting", check_existing)
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
                .str("file", program)
                .str("library", library)
                .str("name", name)
                .opt_str("address", address)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::CreateDefinition { program, address } => client.run_simple(
            Req::new("CreateFunctionDefinitionCmd")
                .str("file", program)
                .str("address", address)
                .build(),
        ),
        Cmd::Delete { program, address } => client.run_simple(
            Req::new("DeleteFunctionCmd")
                .str("file", program)
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
                .str("file", program)
                .str("address", address)
                .str("name", name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::ApplyDataTypes {
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
                    .str("file", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .opt_str("source", Source::opt(source))
                    .bool("createBookmarks", create_bookmarks)
                    .bool("alwaysReplace", always_replace)
                    .build(),
            )
        }
        Cmd::CaptureDataTypes {
            program,
            address,
            address_set,
        } => {
            common::require_address_or_set(&address, &address_set).map_err(common::log_arg_err)?;
            let set = common::address_set(&address_set).map_err(common::log_arg_err)?;
            client.run_simple(
                Req::new("CaptureFunctionDataTypesCmd")
                    .str("file", program)
                    .opt_str("address", address)
                    .opt_json("addressSet", set)
                    .build(),
            )
        }
        Cmd::SetReturnType {
            program,
            address,
            data_type,
            source,
        } => client.run_simple(
            Req::new("SetReturnDataTypeCmd")
                .str("file", program)
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
                .str("file", program)
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
                    .str("file", program)
                    .str("address", address)
                    .str("updateType", update_type.wire())
                    .opt_str("callingConvention", calling_convention)
                    .opt_str("returnType", return_type)
                    .opt_json("parameters", params)
                    .opt_str("source", Source::opt(source))
                    .bool("force", force)
                    .build(),
            )
        }
        Cmd::SetVarargs {
            program,
            address,
            has_var_args,
        } => client.run_simple(
            Req::new("SetFunctionVarArgsCommand")
                .str("file", program)
                .str("address", address)
                .bool("hasVarArgs", has_var_args)
                .build(),
        ),
        Cmd::SetPurge {
            program,
            address,
            purge,
        } => client.run_simple(
            Req::new("SetFunctionPurgeCommand")
                .str("file", program)
                .str("address", address)
                .int("purge", purge)
                .build(),
        ),
        Cmd::SetRepeatableComment {
            program,
            address,
            comment,
        } => client.run_simple(
            Req::new("SetFunctionRepeatableCommentCmd")
                .str("file", program)
                .str("address", address)
                .str("comment", comment)
                .build(),
        ),
        Cmd::Decompile(args) => decompile::run(args, client),
        Cmd::Disassemble(args) => disassemble::run(args, client),
        Cmd::Find(args) => find::run_find(args, client),
        Cmd::Tag { cmd } => tag::run(cmd, client),
        Cmd::Variable { cmd } => variable::run(cmd, client),
        Cmd::SetClassAssociation {
            program,
            address,
            class,
        } => client.run_simple(
            Req::new("FunctionSetClassAssociation")
                .str("file", program)
                .str("address", address)
                .str("class", class)
                .build(),
        ),
        Cmd::SetNamespace {
            program,
            address,
            namespace,
            name,
            source,
        } => client.run_simple(
            Req::new("FunctionSetNamespace")
                .str("file", program)
                .str("address", address)
                .opt_str("namespace", namespace)
                .str("name", name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
    }
}
