//! Class / namespace lifecycle and inspection commands.
//!
//! Mutating verbs: `create-class`, `rename-class`, `delete-class` (plus
//! `function set-class-association` under the `function` group).
//!
//! Read-only inspection verbs: `get-class` returns metadata for a single
//! class (rejects plain namespaces); `list-class` returns the class
//! tree under an optional parent (recursive by default; emits paths only,
//! one per line). Both default to slash-delimited paths so the output of
//! `get-class` and `list-class` can be fed directly into
//! `--class PATH` for the mutating verbs.
//!
//! A class in Ghidra is a `Namespace` whose type is `CLASS` (a
//! `GhidraClass`); it is coupled to a struct in the program's Data Type
//! Manager by NAME ONLY — the decompiler does the lookup. Class and
//! struct are otherwise independent: renaming the class does NOT rename
//! the struct; deleting the class does NOT delete the struct. See the
//! auto-stub caveat on `function set-class-association --help`.

use clap::Subcommand;

use crate::client::Client;
use crate::common::Source;
use crate::json::{Json, Req};

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
    /// Get metadata for a class namespace (class-only; rejects plain
    /// namespaces)
    ///
    /// Prints the class's name, full slash path, parent path, source
    /// type, ID, function member count, child-namespace count, and body
    /// address. The path output is slash-delimited and can be fed
    /// directly into `--class PATH` for the mutating namespace verbs.
    GetClass {
        /// Target file project path (e.g. /Patrician3.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full path of the class (e.g. "/Game/OpMarketTrade")
        #[arg(long)]
        class: String,
        /// Emit the raw server response as JSON (for jq / scripts) [default: false]
        #[arg(long)]
        json: bool,
    },
    /// List class namespaces under an optional parent (paths only)
    ///
    /// Emits one slash-delimited path per line on stdout. Recursive by
    /// default — descends into plain namespaces to find nested classes;
    /// stops descending into classes themselves (matching the GUI's
    /// Symbol Tree). Only CLASS namespaces are listed; plain namespaces
    /// are not.
    ListClass {
        /// Target file project path (e.g. /Patrician3.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Path of the namespace to start from [default: / (root)]
        #[arg(long)]
        parent: Option<String>,
        /// Recurse into plain namespaces to find nested classes [default: true]
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        recursive: bool,
        /// Cap the number of results [default: 0 = unlimited]
        #[arg(long, default_value_t = 0i64)]
        limit: i64,
        /// Emit the raw server `classes` array as JSON (for jq / scripts) [default: false]
        #[arg(long)]
        json: bool,
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
        Cmd::GetClass {
            program,
            class,
            json,
        } => run_get_class(&program, &class, json, client),
        Cmd::ListClass {
            program,
            parent,
            recursive,
            limit,
            json,
        } => run_list_class(
            &program,
            parent.as_deref().map(str::to_string),
            recursive,
            limit,
            json,
            client,
        ),
    }
}

/// Get-class: prints a key/value table for the resolved class. With
/// `--json`, prints the raw server response on stdout. Errors are surfaced
/// by `client.invoke` (logs the server's error message, returns Err(())).
fn run_get_class(program: &str, class: &str, want_json: bool, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("NamespaceGetClass")
            .str("file", program)
            .str("class", class)
            .build(),
    )?;
    if want_json {
        println!("{}", response);
        return Ok(());
    }
    // Render as a small two-column key/value table. Field order matches
    // the server's NamespaceGetClassResponse. Use a left-padded key column
    // (22 chars) so the values line up under a normal terminal.
    let pairs: [(&str, String); 9] = [
        ("name", get_string(&response, "name")),
        ("path", get_string(&response, "path")),
        ("parent", get_string(&response, "parentPath")),
        ("isClass", get_string(&response, "isClass")),
        ("source", get_string(&response, "source")),
        ("id", get_string(&response, "id")),
        ("memberCount", get_string(&response, "memberCount")),
        (
            "childNamespaceCount",
            get_string(&response, "childNamespaceCount"),
        ),
        ("bodyAddress", get_string(&response, "bodyAddress")),
    ];
    for (k, v) in pairs {
        println!("{:<22}{}", k, v);
    }
    Ok(())
}

/// List-class: header on stderr, one path per line on stdout. With
/// `--json`, prints the raw server `classes` array on stdout. With
/// `--limit N`, caps the result and the server returns `truncated: true`.
fn run_list_class(
    program: &str,
    parent: Option<String>,
    recursive: bool,
    limit: i64,
    want_json: bool,
    client: &Client,
) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("NamespaceListClasses")
            .str("file", program)
            .opt_str("parent", parent.clone())
            .bool("recursive", recursive)
            .int("limit", limit)
            .build(),
    )?;

    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let scope = parent.as_deref().unwrap_or("/");

    if want_json {
        // Mirror datatype list --json: print the raw `classes` array
        // verbatim. Scripts that want the count can read it from the
        // server response object directly.
        match response.get("classes") {
            Some(classes) => println!("{}", classes),
            None => println!("[]"),
        }
        return Ok(());
    }

    log::info!(
        "{}: {} class{}{} under {}",
        program,
        count,
        if count == 1 { "" } else { "es" },
        if truncated {
            " (truncated by limit)"
        } else {
            ""
        },
        scope,
    );

    if let Some(classes) = response.get("classes").and_then(Json::as_array) {
        for c in classes {
            let path = c.get("path").and_then(Json::as_str).unwrap_or("?");
            println!("{}", path);
        }
    }
    Ok(())
}

/// Render a server field as a String for the key/value table. gson
/// serializes Java booleans as `true`/`false`; numbers as their decimal
/// form; null fields are dropped from the JSON entirely (gson default),
/// so absent values render as empty string.
fn get_string(response: &Json, key: &str) -> String {
    match response.get(key) {
        Some(Json::Str(s)) => s.clone(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Num(n)) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        Some(Json::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}
