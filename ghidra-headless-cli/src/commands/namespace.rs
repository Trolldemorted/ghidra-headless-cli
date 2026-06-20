//! Class / namespace lifecycle commands.
//!
//! Currently exposes the four class-management procedures on the server
//! (`NamespaceCreateClass`, `NamespaceRenameClass`, `NamespaceDeleteClass`,
//! plus `FunctionSetClassAssociation` under the `function` group). A class
//! in Ghidra is a `Namespace` whose type is `CLASS` (a `GhidraClass`); it is
//! coupled to a struct in the program's Data Type Manager by NAME ONLY —
//! the decompiler does the lookup. Class and struct are otherwise
//! independent: renaming the class does NOT rename the struct; deleting the
//! class does NOT delete the struct. See the auto-stub caveat on
//! `function set-class-association --help`.

use clap::Subcommand;

use crate::client::Client;
use crate::common::Source;
use crate::json::Req;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a new class namespace, or convert an existing plain
    /// namespace into a class
    ///
    /// Two modes (mutually exclusive):
    ///   * `--parent /Foo --name Bar`  → fresh class Bar under namespace Foo
    ///   * `--from-namespace /Foo/Bar` → convert existing plain namespace
    ///     Bar into a class (its body / children survive; the namespace's
    ///     type flips from NAMESPACE to CLASS).
    ///
    /// Class names are resolved against the program's DTM by name at
    /// decompile time. There is NO automatic struct creation here — the
    /// struct lookup happens on function association (and may auto-stub
    /// one if absent; see `function set-class-association --help`).
    CreateClass {
        /// Target file project path (e.g. /Patrician3.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Path of an existing parent namespace under which to create a
        /// fresh class (e.g. "/Game"). Required for the `--name` mode.
        #[arg(long, conflicts_with = "from_namespace")]
        parent: Option<String>,
        /// Path of an existing plain namespace to convert into a class
        /// (e.g. "/Game/OldNamespace"). Mutually exclusive with `--parent`.
        #[arg(long, conflicts_with = "parent")]
        from_namespace: Option<String>,
        /// Bare name (no slash) of the new class when `--parent` is used.
        /// Required for the `--parent` mode; ignored with `--from-namespace`.
        #[arg(long)]
        name: Option<String>,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Rename a class namespace (does NOT rename any matching struct)
    ///
    /// Pure namespace rename — does not touch the program's Data Type
    /// Manager. If a struct with the old name exists, it stays; if you
    /// want the struct renamed too, run `datatype edit --path /X --name
    /// NewName` separately. Class and struct are independent; sharing
    /// only a name.
    RenameClass {
        /// Target file project path (e.g. /Patrician3.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full path of the class to rename (e.g. "/Game/OldName")
        #[arg(long)]
        class: String,
        /// New bare name (no slash)
        #[arg(long)]
        name: String,
        /// Symbol source type [default: user-defined]
        #[arg(long, value_enum)]
        source: Option<Source>,
    },
    /// Delete a class namespace (does NOT delete any matching struct)
    ///
    /// Removes the class symbol only. The struct (if any) in the program's
    /// Data Type Manager is left untouched — to delete it, run `datatype
    /// delete --name <ClassName>` separately. Children of the class
    /// (functions, sub-namespaces) become orphans under the parent
    /// namespace, matching the GUI's right-click → Delete on a class.
    ///
    /// This verb only deletes classes — passing a plain namespace's path
    /// returns an error.
    DeleteClass {
        /// Target file project path (e.g. /Patrician3.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full path of the class to delete (e.g. "/Game/MyClass")
        #[arg(long)]
        class: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::CreateClass {
            program,
            parent,
            from_namespace,
            name,
            source,
        } => client.run_simple(
            Req::new("NamespaceCreateClass")
                .str("file", program)
                .opt_str("parent", parent)
                .opt_str("fromNamespace", from_namespace)
                .opt_str("name", name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::RenameClass {
            program,
            class,
            name,
            source,
        } => client.run_simple(
            Req::new("NamespaceRenameClass")
                .str("file", program)
                .str("class", class)
                .str("name", name)
                .opt_str("source", Source::opt(source))
                .build(),
        ),
        Cmd::DeleteClass { program, class } => client.run_simple(
            Req::new("NamespaceDeleteClass")
                .str("file", program)
                .str("class", class)
                .build(),
        ),
    }
}
