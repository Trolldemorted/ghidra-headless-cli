//! Data-type management: list / show / create / replace / edit / delete.
//!
//! These wire to the `ListDataTypes`, `ShowDataType`, `CreateDataType`,
//! `ReplaceDataType`, `EditDataType`, and `DeleteDataType` RPC procedures.
//!
//! Path syntax mirrors the server: a leading slash, category segments
//! separated by slashes, name as the last segment. Examples: `/int`,
//! `/ELF/Elf64_Ehdr`, `/MyCategory/MyStruct`.
//!
//! Complex payload fields (`--fields` for struct/union, `--entries` for
//! enum) are accepted as JSON literals on the command line. Both are arrays
//! of objects: `[{"name":"x","type":"int"}]` and `[{"name":"RED","value":0}]`.
//!
//! NOTE: `datatype apply` was removed; it now lives under `memory apply-type`
//! because it operates on program memory (laying a type at an address),
//! not on the DTM.
//!
//! NOTES on C snippets:
//!
//!   stdint.h types: Ghidra's CParser does NOT ship `intN_t` or `uintN_t`
//!   typedefs. Both signed AND unsigned variants fail when used in
//!   `--definition` and `--fields` snippets (`Undefined data type
//!   "uint8_t"`). Define each one once before use, e.g.:
//!
//!       --definition "typedef long long int64_t;"
//!       --definition "typedef unsigned long long uint64_t;"
//!       --definition "typedef unsigned char uint8_t;"
//!
//!   No preprocessor: Ghidra's CParser is not a C preprocessor. `#define`,
//!   `#include`, `#ifdef`, and `#ifndef` directives are rejected. Use the
//!   actual values they would expand to, or define the type once via
//!   `--definition` first. `#pragma pack(N)` IS supported.
//!
//!   Built-in C tokens that DO work without preprocessing: `sizeof`,
//!   `NULL`, integer limits like `INT_MAX`.
//!
//! See `notes/procedures/CreateDataType.md` for full details.

use std::collections::BTreeMap;

use clap::Subcommand;

use crate::client::Client;
use crate::common;
use crate::json::{Json, Req};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List data types under a category
    List {
        /// Target file project path (e.g. /test/foo.exe)
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Category path to start from [default: / (root)]
        #[arg(long)]
        category: Option<String>,
        /// Recurse into subcategories [default: true]
        #[arg(long)]
        recursive: Option<bool>,
        /// Keep only this kind: struct|union|enum|typedef|all [default: all]
        #[arg(long)]
        kind: Option<String>,
        /// Cap the number of results [default: 0 = unlimited]
        #[arg(long)]
        limit: Option<i64>,
        /// Emit the raw server `types[]` array as JSON (for jq / scripts) [default: false]
        #[arg(long)]
        json: bool,
    },
    /// Show a single data type (kind/fields/entries/etc.). Use either --path
    /// OR (--name + optional --archive / --category) — not both, not neither.
    Show {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path, e.g. /ELF/Elf64_Ehdr. Archive-qualified
        /// paths from `datatype list` output (e.g.
        /// `/Patrician3.exe-aa1fd4 (archive)/MainMenuLoaderScreen`) are
        /// accepted; the ` (archive)` suffix is stripped automatically.
        /// Mutually exclusive with --name.
        #[arg(long, conflicts_with = "name")]
        path: Option<String>,
        /// Leaf type name (e.g. `MainMenuLoaderScreen`). Searched first
        /// in the program DTM, then in every open source archive. With
        /// --archive, scoped to that archive; with --category, scoped to
        /// that category. Mutually exclusive with --path.
        #[arg(long, conflicts_with = "path")]
        name: Option<String>,
        /// Source archive name (e.g. `windows_vs`, `Patrician3.exe-aa1fd4`).
        /// The ` (archive)` suffix shown by `datatype list` is stripped.
        /// Use with --name to disambiguate when the same leaf name lives
        /// in multiple archives.
        #[arg(long, requires = "name")]
        archive: Option<String>,
        /// Category path (e.g. /Demangler). Use with --name to scope
        /// the program-DTM search to a single category.
        #[arg(long, requires = "name")]
        category: Option<String>,
        /// Emit the raw JSON `detail` object instead of the C declaration [default: false]
        #[arg(long)]
        json: bool,
        /// Emit the full dependency graph (builtins preamble + every
        /// transitively-referenced type) instead of just the requested
        /// type. By default the server filters the writer output to the
        /// requested type's C block; pass --with-deps to opt into the
        /// raw writer output (same as the GUI's "Export C"). [default: false]
        #[arg(long)]
        with_deps: bool,
    },
    /// Create a struct / union / enum / typedef
    Create {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// One of: struct, union, enum, typedef [default: required unless --definition is given]
        #[arg(long)]
        kind: Option<String>,
        /// New type name [default: required unless --definition OR --path is given;
        /// when --definition is given, --name IS forwarded to the server
        /// (the snippet's embedded name must match --name)]
        #[arg(long)]
        name: Option<String>,
        /// Target category path [default: /]
        #[arg(long)]
        category: Option<String>,
        /// Full definition as a C snippet: "struct Foo { int x; char *name; };".
        /// When given, --kind becomes optional (the parsed type's kind is
        /// used) and --fields/--entries/--base are ignored. --name is
        /// still required unless --path is given: it's forwarded to the
        /// server to determine where the new type lands, and the snippet's
        /// embedded name must match --name. Anonymous snippets
        /// ("struct { int x; };") return an error — the snippet must
        /// declare a name. The conflict policy differs: `create` errors
        /// on a name clash; `replace` overwrites in place.
        ///
        /// Notes:
        ///
        ///   Anonymous NESTED types ("union U { struct { int x; } s; };") are
        ///   valid C; CParser auto-names them `_struct_N` (suffixing `.conflict`
        ///   on collision). Name nested types explicitly if you want
        ///   predictable field types.
        ///
        ///   stdint.h types (`intN_t`, `uintN_t`) are NOT in CParser's
        ///   built-in map — both signed and unsigned variants fail with
        ///   `Undefined data type "uint8_t"` when used in fields. Define each
        ///   once before use, e.g. `--definition "typedef long long int64_t;"`
        ///   or `--definition "typedef unsigned char uint8_t;"`.
        ///
        ///   No C preprocessor: `#define`, `#include`, `#ifdef`, `#ifndef`
        ///   directives are REJECTED. Use the expanded values directly, or
        ///   pre-define types via `--definition`. `#pragma pack(N)` IS
        ///   supported. Built-in tokens `sizeof`, `NULL`, `INT_MAX` etc. work
        ///   without preprocessing.
        #[arg(long)]
        definition: Option<String>,
        /// Fields as a JSON array (struct/union): [{"name":"x","type":"int"}]
        #[arg(long)]
        fields: Option<String>,
        /// Entries as a JSON array (enum): [{"name":"RED","value":0}]
        #[arg(long)]
        entries: Option<String>,
        /// Base type as a C-syntax expression (typedef): "int", "char *", "byte[16]"
        #[arg(long)]
        base: Option<String>,
        /// Enum byte width [default: 4]
        #[arg(long)]
        enum_size: Option<i64>,
    },
    /// Create or REPLACE a struct / union / enum / typedef (silently overwrites
    /// on name collision; references preserved). Same input shape as `create`.
    Replace {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path (e.g. /Demangler/L_String). Disambiguates when
        /// the same name appears in multiple categories (as with archive
        /// stubs). Mutually exclusive with --name+--category.
        #[arg(long, value_name = "PATH", conflicts_with = "name")]
        path: Option<String>,
        /// One of: struct, union, enum, typedef [default: required unless --definition is given]
        #[arg(long)]
        kind: Option<String>,
        /// New type name [default: required unless --definition OR --path is given;
        /// when --definition is given, --name IS forwarded to the server
        /// (the snippet's embedded name must match --name)]
        #[arg(long)]
        name: Option<String>,
        /// Target category path [default: /]
        #[arg(long)]
        category: Option<String>,
        /// Full definition as a C snippet: "struct Foo { int x; char *name; };".
        /// When given, --kind becomes optional (the parsed type's kind is
        /// used) and --fields/--entries/--base are ignored. --name is
        /// still required unless --path is given: it's forwarded to the
        /// server to determine where the new type lands, and the snippet's
        /// embedded name must match --name. Anonymous snippets
        /// ("struct { int x; };") return an error — the snippet must
        /// declare a name. The conflict policy differs: `create` errors
        /// on a name clash; `replace` overwrites in place.
        ///
        /// Notes:
        ///
        ///   Anonymous NESTED types ("union U { struct { int x; } s; };") are
        ///   valid C; CParser auto-names them `_struct_N` (suffixing `.conflict`
        ///   on collision). Name nested types explicitly if you want
        ///   predictable field types.
        ///
        ///   stdint.h types (`intN_t`, `uintN_t`) are NOT in CParser's
        ///   built-in map — both signed and unsigned variants fail with
        ///   `Undefined data type "uint8_t"` when used in fields. Define each
        ///   once before use, e.g. `--definition "typedef long long int64_t;"`
        ///   or `--definition "typedef unsigned char uint8_t;"`.
        ///
        ///   No C preprocessor: `#define`, `#include`, `#ifdef`, `#ifndef`
        ///   directives are REJECTED. Use the expanded values directly, or
        ///   pre-define types via `--definition`. `#pragma pack(N)` IS
        ///   supported. Built-in tokens `sizeof`, `NULL`, `INT_MAX` etc. work
        ///   without preprocessing.
        #[arg(long)]
        definition: Option<String>,
        /// Fields as a JSON array (struct/union): [{"name":"x","type":"int"}]
        #[arg(long)]
        fields: Option<String>,
        /// Entries as a JSON array (enum): [{"name":"RED","value":0}]
        #[arg(long)]
        entries: Option<String>,
        /// Base type as a C-syntax expression (typedef): "int", "char *", "byte[16]"
        #[arg(long)]
        base: Option<String>,
        /// Enum byte width [default: 4]
        #[arg(long)]
        enum_size: Option<i64>,
    },
    /// Edit an existing data type (batched: rename/move/description/addFields/replaceFields/addEntries)
    Edit {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path
        #[arg(long)]
        path: String,
        /// New name [default: unchanged]
        #[arg(long)]
        rename: Option<String>,
        /// Move to a new category [default: unchanged]
        #[arg(long)]
        move_to: Option<String>,
        /// Type-level description (the free-text doc comment shown in the
        /// Data Type Manager). Pass "" to clear. [default: unchanged]
        ///
        /// Not supported on typedefs: Ghidra's TypedefDataType does not
        /// override DataType.setDescription, so the call throws
        /// UnsupportedOperationException. The server surfaces a clear
        /// "edit the underlying type instead" error. Field and variant
        /// comments have their own subcommands (see `set-field-comment` /
        /// `set-variant-comment` below).
        #[arg(long)]
        description: Option<String>,
        /// Drop all existing fields before adding (struct/union) [default: false]
        #[arg(long)]
        replace_fields: Option<bool>,
        /// Fields to append as a C snippet: "struct { long long sum; char tag; };".
        /// The target type's name is auto-injected for anonymous snippets. The
        /// snippet's kind must match the target (struct/union/enum); mismatch
        /// returns an error before commit.
        #[arg(long)]
        definition: Option<String>,
        /// Fields to append (JSON array, struct/union)
        #[arg(long)]
        add_fields: Option<String>,
        /// Entries to append (JSON array, enum)
        #[arg(long)]
        add_entries: Option<String>,
    },
    /// Set the comment on a single struct/union field (by name or index).
    /// Pass --comment "" to clear. Not supported on enums, typedefs, or built-ins.
    SetFieldComment {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path
        #[arg(long)]
        path: String,
        /// Field name OR zero-based index. Names match the first field; if
        /// multiple fields share a name the call errors and asks for an
        /// index.
        #[arg(long)]
        field: String,
        /// New field comment. Pass "" to clear. Required (use "" to clear).
        #[arg(long)]
        comment: String,
    },
    /// Set the comment on a single enum variant. Pass --comment "" to clear.
    /// Not supported on structs, typedefs, or built-ins.
    SetVariantComment {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path
        #[arg(long)]
        path: String,
        /// Variant name (must already exist on the enum).
        #[arg(long)]
        variant: String,
        /// New variant comment. Pass "" to clear. Required (use "" to clear).
        #[arg(long)]
        comment: String,
    },
    /// Delete a user-defined data type by full path (built-ins are rejected)
    Delete {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path
        #[arg(long)]
        path: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::List {
            program,
            category,
            recursive,
            kind,
            limit,
            json,
        } => {
            // Compute the print_list args BEFORE moving the strings
            // into the RPC builder. We clone all three short strings
            // (file path, optional category, optional kind) so the
            // owned values can be moved into `str`/`opt_str` below
            // while the printer still gets references with the same
            // text. Negligible cost (≤ ~256 bytes each).
            let program_for_print = program.clone();
            let program_ref: &str = &program_for_print;
            let category_for_print = category.clone();
            let category_ref: Option<&str> = category_for_print.as_deref();
            let kind_for_print = kind.clone();
            let kind_ref: Option<&str> = kind_for_print.as_deref();
            let recursive_flag = recursive.unwrap_or(true);
            let response = client.invoke(
                Req::new("ListDataTypes")
                    .str("file", program)
                    .opt_str("category", category)
                    .opt_bool("recursive", recursive)
                    .opt_str("kind", kind)
                    .opt_int("limit", limit)
                    .build(),
            )?;
            print_list(
                &response,
                program_ref,
                category_ref,
                recursive_flag,
                kind_ref,
                json,
            )?;
            Ok(())
        }
        Cmd::Show {
            program,
            path,
            name,
            archive,
            category,
            json,
            with_deps,
        } => {
            // Server enforces "exactly one of path / name" — we let clap
            // reject the "both" case at parse time, and the empty-string
            // case is handled by clap via Option<String> + requires/conflicts_with.
            // Re-check here for the "neither" case so a `--path ""` slips through
            // clap but still gets caught.
            if path.is_none() && name.is_none() {
                return Err(common::log_arg_err(
                    "Pass either --path (e.g. /Category/Name) or --name (with \
                     optional --archive / --category); not neither."
                        .to_string(),
                ));
            }
            let mut req = Req::new("ShowDataType").str("file", program);
            if let Some(p) = path {
                req = req.str("path", p);
            }
            if let Some(n) = name {
                req = req.str("name", n);
                if let Some(a) = archive {
                    req = req.str("archive", a);
                }
                if let Some(c) = category {
                    req = req.str("category", c);
                }
            }
            if with_deps {
                req = req.opt_bool("with_deps", Some(true));
            }
            let response = client.invoke(req.build())?;
            print_show(&response, json)?;
            Ok(())
        }
        Cmd::Create {
            program,
            kind,
            name,
            category,
            definition,
            fields,
            entries,
            base,
            enum_size,
        } => run_create_or_replace(
            "CreateDataType",
            program,
            kind,
            name,
            category,
            definition,
            fields,
            entries,
            base,
            enum_size,
            client,
        ),
        Cmd::Replace {
            program,
            path,
            kind,
            name,
            category,
            definition,
            fields,
            entries,
            base,
            enum_size,
        } => run_replace(
            program, path, kind, name, category, definition, fields, entries, base, enum_size,
            client,
        ),
        Cmd::Edit {
            program,
            path,
            rename,
            move_to,
            description,
            replace_fields,
            definition,
            add_fields,
            add_entries,
        } => {
            let add_fields_json = parse_opt_json("addFields", add_fields)?;
            let add_entries_json = parse_opt_json("addEntries", add_entries)?;
            // --definition wins over explicit --add-fields/--add-entries JSON.
            let (add_fields_json, add_entries_json) = if definition.is_some() {
                (None, None)
            } else {
                (add_fields_json, add_entries_json)
            };
            let response = client.invoke(
                Req::new("EditDataType")
                    .str("file", program)
                    .str("path", path)
                    .opt_str("rename", rename)
                    .opt_str("move", move_to)
                    .opt_str("description", description)
                    .opt_bool("replaceFields", replace_fields)
                    .opt_str("definition", definition)
                    .opt_json("addFields", add_fields_json)
                    .opt_json("addEntries", add_entries_json)
                    .build(),
            )?;
            print_show(&response, false)?;
            Ok(())
        }
        Cmd::SetFieldComment {
            program,
            path,
            field,
            comment,
        } => {
            let response = client.invoke(
                Req::new("SetDataTypeFieldComment")
                    .str("file", program)
                    .str("path", path)
                    .str("field", field)
                    .str("comment", comment)
                    .build(),
            )?;
            print_field_comment(&response)?;
            Ok(())
        }
        Cmd::SetVariantComment {
            program,
            path,
            variant,
            comment,
        } => {
            let response = client.invoke(
                Req::new("SetDataTypeVariantComment")
                    .str("file", program)
                    .str("path", path)
                    .str("variant", variant)
                    .str("comment", comment)
                    .build(),
            )?;
            print_variant_comment(&response)?;
            Ok(())
        }
        Cmd::Delete { program, path } => {
            let response = client.invoke(
                Req::new("DeleteDataType")
                    .str("file", program)
                    .str("path", path)
                    .build(),
            )?;
            let deleted = response
                .get("deleted")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            log::info!(
                "{} {}",
                if deleted { "deleted" } else { "NOT deleted" },
                response.get("path").and_then(Json::as_str).unwrap_or("?")
            );
            // If the deleted type was referenced by other composites, those
            // composites now hold `-BAD-` placeholders in their field lists
            // until each referrer is re-resolved (via `datatype replace` of
            // the referrer, or delete + create of the referrer). The server
            // returns the list under `referrers`; surface it on stderr so
            // the user knows what to heal.
            if let Some(arr) = response.get("referrers").and_then(Json::as_array) {
                if !arr.is_empty() {
                    log::info!(
                        "note: {} type(s) referenced this and now show '-BAD-'; \
                         run `datatype replace` on each to heal:",
                        arr.len()
                    );
                    for r in arr {
                        // `arr` is `&[Json]`; each element is `&Json`. as_str
                        // borrows from the Json so we keep the lifetime
                        // straight by matching rather than unwrapping.
                        let p = match r {
                            Json::Str(s) => s.as_str(),
                            _ => "?",
                        };
                        log::info!("  {}", p);
                    }
                }
            }
            Ok(())
        }
    }
}

/// Parse a user-supplied JSON literal (or None) and emit a clear error on
/// malformed input. Used for the `--fields` and `--entries` arrays.
fn run_create_or_replace(
    procedure: &'static str,
    program: String,
    kind: Option<String>,
    name: Option<String>,
    category: Option<String>,
    definition: Option<String>,
    fields: Option<String>,
    entries: Option<String>,
    base: Option<String>,
    enum_size: Option<i64>,
    client: &Client,
) -> Result<(), ()> {
    // --definition wins over the explicit JSON arrays: when both are
    // supplied the C snippet is authoritative (lets a user write the
    // definition once and not have to mirror it as JSON). --kind and
    // --name are optional on this path; the snippet's embedded kind
    // and name are used.
    // --definition wins over the explicit JSON arrays: when both are
    // supplied the C snippet is authoritative and --fields/--entries/--base
    // are ignored. --kind is also optional on this path (the snippet's
    // embedded kind is used). --name IS forwarded to the server, however:
    // the server uses `name` to compute the target path (the snippet's
    // embedded name must match `name`, and the new type lands at
    // category+name). If the user only passes --definition and no
    // --name and no --path, the server returns "Missing 'name'", which
    // is the right behavior — it forces the user to be explicit about
    // where the new type lands.
    let (kind, name, fields_json, entries_json, base) = if definition.is_some() {
        (kind, name, None, None, None)
    } else {
        let k = kind.ok_or_else(|| {
            common::log_arg_err("--kind is required (or pass --definition)".to_string())
        })?;
        let n = name.ok_or_else(|| {
            common::log_arg_err("--name is required (or pass --definition)".to_string())
        })?;
        let f = parse_opt_json("fields", fields)?;
        let e = parse_opt_json("entries", entries)?;
        (Some(k), Some(n), f, e, base)
    };
    let response = client.invoke(
        Req::new(procedure)
            .str("file", program)
            .opt_str("kind", kind)
            .opt_str("name", name)
            .opt_str("category", category)
            .opt_str("definition", definition)
            .opt_json("fields", fields_json)
            .opt_json("entries", entries_json)
            .opt_str("base", base)
            .opt_int("enumSize", enum_size)
            .build(),
    )?;
    print_show(&response, false)?;
    Ok(())
}

/// `datatype replace` dispatch. Mirrors `run_create_or_replace` but adds
/// `--path` (preferred when the same name appears in multiple categories,
/// as with archive stubs). On the path form, `--name` and `--category`
/// are derived from the path and conflicts_with blocks them; the user
/// still supplies `--kind` (or `--definition`).
fn run_replace(
    program: String,
    path: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    category: Option<String>,
    definition: Option<String>,
    fields: Option<String>,
    entries: Option<String>,
    base: Option<String>,
    enum_size: Option<i64>,
    client: &Client,
) -> Result<(), ()> {
    // --definition wins over the explicit JSON arrays: when given, the
    // C snippet is authoritative and --fields/--entries/--base are
    // ignored. --kind is also optional on this path (the snippet's
    // embedded kind is used).
    //
    // --name forwarding: --name IS forwarded to the server when
    // --definition is given AND --path is NOT (because the server uses
    // `name` to compute the target path, and verifies the snippet's
    // embedded name matches). If --path is given, the server derives
    // name+category from it (clap's conflicts_with blocks --name then
    // anyway, but we keep the code defensive).
    //
    // On the non-definition path, --name is required unless --path is
    // given.
    let (kind, name, fields_json, entries_json, base) = if definition.is_some() {
        // --definition form: snippet is authoritative; --kind optional
        // (from snippet); --name forwarded (required by server unless
        // --path is also given); --fields/--entries/--base ignored.
        (kind, name, None, None, None)
    } else if path.is_some() {
        // --path provides name+category; --kind, --fields/--entries, --base
        // still come from the user.
        let k = kind.ok_or_else(|| {
            common::log_arg_err("--kind is required (or pass --definition)".to_string())
        })?;
        let f = parse_opt_json("fields", fields)?;
        let e = parse_opt_json("entries", entries)?;
        (Some(k), None, f, e, base)
    } else {
        let k = kind.ok_or_else(|| {
            common::log_arg_err("--kind is required (or pass --definition/--path)".to_string())
        })?;
        let n = name.ok_or_else(|| {
            common::log_arg_err("--name is required (or pass --definition/--path)".to_string())
        })?;
        let f = parse_opt_json("fields", fields)?;
        let e = parse_opt_json("entries", entries)?;
        (Some(k), Some(n), f, e, base)
    };
    let response = client.invoke(
        Req::new("ReplaceDataType")
            .str("file", program)
            .opt_str("path", path)
            .opt_str("kind", kind)
            .opt_str("name", name)
            .opt_str("category", category)
            .opt_str("definition", definition)
            .opt_json("fields", fields_json)
            .opt_json("entries", entries_json)
            .opt_str("base", base)
            .opt_int("enumSize", enum_size)
            .build(),
    )?;
    print_show(&response, false)?;
    Ok(())
}

fn parse_opt_json(name: &str, value: Option<String>) -> Result<Option<Json>, ()> {
    match value {
        None => Ok(None),
        Some(text) => Json::parse(&text)
            .map(Some)
            .map_err(|e| common::log_arg_err(format!("invalid JSON for --{}: {}", name, e))),
    }
}

fn print_list(
    response: &Json,
    file: &str,
    category: Option<&str>,
    recursive: bool,
    kind: Option<&str>,
    want_json: bool,
) -> Result<(), ()> {
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);

    // ---- --json path: dump the raw server `types[]` array verbatim.
    //
    // The output is the raw ndjson-style JSON the server returned, so
    // consumers can pipe to `jq`. We print the array on a single line
    // (the server's own serializer keeps it compact), which jq parses
    // directly. A `head -1` then sees just `[` — for a quick smoke test
    // of "did the server return anything", `jq 'length'` is the move.
    if want_json {
        if let Some(types) = response.get("types") {
            println!("{}", types);
        } else {
            // No `types` key on error responses — surface the error so
            // the script doesn't silently get empty output.
            if let Some(err) = response.get("error").and_then(Json::as_str) {
                return Err(common::log_arg_err(err.to_string()));
            }
            println!("[]");
        }
        return Ok(());
    }

    // ---- Tree path.
    //
    // Header on stderr so scripts that `2>/dev/null` get the tree alone
    // on stdout. Includes the file + category + filter context so the
    // user always knows what scope they're looking at.
    let scope = category.unwrap_or("/");
    let kind_str = match kind {
        None | Some("") | Some("all") => "all kinds".to_string(),
        Some(k) => format!("kind={}", k),
    };
    let recurse_str = if recursive {
        "recursive"
    } else {
        "non-recursive"
    };
    log::info!(
        "{}: {} type{}{} ({}, {}, {})",
        file,
        count,
        if count == 1 { "" } else { "s" },
        if truncated { " (truncated)" } else { "" },
        recurse_str,
        scope,
        kind_str,
    );

    let arr = match response.get("types").and_then(Json::as_array) {
        Some(a) => a,
        None => return Ok(()), // success but empty (no types key — defensive)
    };
    let rows: Vec<TypeRow> = arr.iter().map(TypeRow::from_json).collect();

    if rows.is_empty() {
        // Distinguish "filter matched nothing" from "category is empty" —
        // both are useful diagnostics.
        log::info!("(no types matched)");
        return Ok(());
    }

    let scope_root = category.unwrap_or("/");
    print_tree(&rows, scope_root);
    Ok(())
}

/// One row of the server's `types[]` array, flattened into typed fields.
struct TypeRow {
    name: String,
    kind: String,
    size: i64,
    /// Full path, e.g. "/Demangler/L_String" or "/ClaudeHeadlessStruct".
    path: String,
    /// Coarse source: "USER" | "BUILTIN" | "ARCHIVE" (or unknown).
    source: String,
    /// Optional archive name (e.g. "windows_vs", "Mapeditor.exe").
    source_archive: Option<String>,
}

impl TypeRow {
    fn from_json(j: &Json) -> TypeRow {
        let path = j
            .get("path")
            .and_then(Json::as_str)
            .unwrap_or("/?")
            .to_string();
        let name = j
            .get("name")
            .and_then(Json::as_str)
            .map(String::from)
            .unwrap_or_else(|| {
                // Fall back to the last path segment if `name` is missing.
                path.rsplit_once('/')
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_else(|| path.clone())
            });
        TypeRow {
            name,
            kind: j
                .get("kind")
                .and_then(Json::as_str)
                .unwrap_or("?")
                .to_string(),
            size: j.get("size").and_then(Json::as_f64).unwrap_or(0.0) as i64,
            path,
            source: j
                .get("source")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            source_archive: j
                .get("sourceArchive")
                .and_then(Json::as_str)
                .map(String::from),
        }
    }

    /// Human-readable source label per the format in the plan:
    /// `program (user)` / `built-in (builtin)` / `<archive> (builtin)`
    /// / `<archive> (archive)`.
    fn source_label(&self) -> String {
        match (self.source.as_str(), self.source_archive.as_deref()) {
            ("USER", _) => "program (user)".to_string(),
            ("BUILTIN", None) => "built-in (builtin)".to_string(),
            ("BUILTIN", Some(a)) => format!("{} (builtin)", a),
            ("ARCHIVE", Some(a)) => format!("{} (archive)", a),
            ("ARCHIVE", None) => "? (archive)".to_string(),
            (other, _) if !other.is_empty() => other.to_string(),
            _ => "?".to_string(),
        }
    }

    /// Category path component: everything in `path` before the last `/`.
    /// `/ClaudeHeadlessStruct` -> "/" (root category); `/Demangler/L_String`
    /// -> "/Demangler". Trailing slashes normalized away.
    fn category_path(&self) -> String {
        match self.path.rsplit_once('/') {
            Some((cat, _)) => {
                if cat.is_empty() {
                    "/".to_string()
                } else {
                    cat.to_string()
                }
            }
            None => "/".to_string(),
        }
    }
}

/// Print `rows` as a tree grouped by category path under the given
/// `scope_root`.
///
/// `scope_root` is the category the user asked for (defaults to `/`).
/// Types whose `category_path()` equals `scope_root` print flush-left
/// with no connector; types under subcategories of `scope_root` print
/// with the standard tree indenting.
///
/// Layout (matches the approved preview):
///   - "Root-level" types (category == scope_root) sit flush-left
///     with NO connector.
///   - Each child category prints as a `<lastSeg>/` header. If the
///     child is a direct child of the scope root, the header is
///     flush-left; deeper headers carry `├── ` / `└── `.
///   - Types under a category are indented one level deeper with
///     `├── ` / `└── ` connectors.
///   - Only the LAST segment of each category path is shown in the
///     header — the indentation conveys the full path. A row at
///     `/Demangler/std/ios_base` lives under `Demangler/std/ios_base/`
///     in the tree.
///
/// The DTM allows empty intermediate categories: a row at
/// `/Demangler/std/ios_base` doesn't imply `/Demangler` or
/// `/Demangler/std` have direct rows. We synthesize their headers
/// so the user can see the full path context.
fn print_tree(rows: &[TypeRow], scope_root: &str) {
    // Group by category path.
    let mut by_cat: BTreeMap<String, Vec<&TypeRow>> = BTreeMap::new();
    for r in rows {
        by_cat.entry(r.category_path()).or_default().push(r);
    }

    // Snapshot of all category paths the server returned. Used to
    // find children at deeper levels even when intermediate
    // categories have no direct rows.
    let known_paths: Vec<String> = by_cat.keys().cloned().collect();

    // "Root" rows for this view: types whose category IS the scope
    // root. For the un-scoped (`scope_root == "/"`) case this is the
    // program's top-level DTM. For a scoped call like
    // `--category /Demangler`, this is types living directly in
    // `/Demangler` (rare — the server usually returns sub-categories
    // like `/Demangler/std` rather than `/Demangler` itself).
    let root_rows = by_cat.remove(scope_root).unwrap_or_default();
    print_rows_flat(&root_rows);

    // Walk children of the scope root. Skip the scope-root itself
    // (already represented as the flush-left rows above).
    let root_children: Vec<String> = known_paths
        .iter()
        .filter(|p| *p != scope_root && is_immediate_child(p, scope_root))
        .cloned()
        .collect();
    for (i, child_path) in root_children.iter().enumerate() {
        // `child_indent` is the prefix for THIS category's header
        // line. For root-level categories it's "" (flush-left); for
        // nested categories the caller computes the indent by
        // prepending "    " (4 spaces) per level of nesting.
        let child_indent = String::new();
        print_category(
            child_path,
            &child_indent,
            &mut by_cat,
            &known_paths,
            true, /* parent_is_root_level */
            i,
            root_children.len(),
        );
    }
}

/// Print a category header + its rows + nested children.
///
/// `indent` — the prefix already printed on the line where THIS
/// header sits. For root-level categories it's "" (flush-left); for
/// nested categories it's the accumulated indentation of the parent
/// chain (4 spaces per level).
///
/// `parent_is_root_level` — true when the parent of this category is
/// the scope root. In that case the header itself is flush-left
/// (matches the user preview).
fn print_category(
    path: &str,
    indent: &str,
    by_cat: &mut BTreeMap<String, Vec<&TypeRow>>,
    known_paths: &[String],
    parent_is_root_level: bool,
    sibling_idx: usize,
    sibling_count: usize,
) {
    let cat_rows: Vec<&TypeRow> = by_cat.remove(path).unwrap_or_default();
    let last_seg = last_segment(path);
    let cat_header = format!("{}/", last_seg);

    // The connector for THIS header line. For root-level categories
    // the user preview shows no connector (just `Demangler/` flush-
    // left). For deeper categories, the connector is `├── ` or
    // `└── ` depending on whether this is the last sibling at its
    // level.
    let conn = if parent_is_root_level {
        ""
    } else {
        if sibling_idx + 1 == sibling_count {
            "└── "
        } else {
            "├── "
        }
    };
    println!("{}{}{}", indent, conn, cat_header);

    // Print rows directly in this category (if any). Each row gets
    // an extra 4-space indent (one nesting level deeper than the
    // header) plus the standard `├── ` / `└── ` connector.
    if !cat_rows.is_empty() {
        let (name_w, kind_w) = widths_for(&cat_rows);
        let row_indent = format!("{}    ", indent);
        for (i, r) in cat_rows.iter().enumerate() {
            let last = i + 1 == cat_rows.len();
            let row_conn = if last { "└── " } else { "├── " };
            print_row(&format!("{}{}", row_indent, row_conn), r, name_w, kind_w);
        }
    }

    // Recurse into immediate child categories. Pass sibling info so
    // each child knows its own connector; child indent is 4 spaces
    // deeper than this category's indent.
    let children: Vec<String> = known_paths
        .iter()
        .filter(|p| is_immediate_child(p, path))
        .cloned()
        .collect();
    let child_indent = format!("{}    ", indent);
    for (i, child_path) in children.iter().enumerate() {
        print_category(
            child_path,
            &child_indent,
            by_cat,
            known_paths,
            false,
            i,
            children.len(),
        );
    }
}

/// Print a slice of root-level rows flush-left with no connector.
fn print_rows_flat(rows: &[&TypeRow]) {
    if rows.is_empty() {
        return;
    }
    let (name_w, kind_w) = widths_for(rows);
    for r in rows {
        print_row("", r, name_w, kind_w);
    }
}

/// Compute column widths (name, kind) for a slice of rows.
fn widths_for(rows: &[&TypeRow]) -> (usize, usize) {
    let mut name_w = 0usize;
    let mut kind_w = 0usize;
    for r in rows {
        if r.name.chars().count() > name_w {
            name_w = r.name.chars().count();
        }
        if r.kind.chars().count() > kind_w {
            kind_w = r.kind.chars().count();
        }
    }
    if name_w < 4 {
        name_w = 4;
    }
    if kind_w < 6 {
        kind_w = 6;
    }
    (name_w, kind_w)
}

/// True when `child_path` is exactly one level below `parent`.
///
/// For root parent (`""`), immediate children are paths like "/PE"
/// or "/Demangler"; "/Demangler/std" is two levels deep and its
/// immediate parent is "/Demangler" (synthesized).
///
/// For non-root parent like "/PE" or "/Demangler", immediate children
/// are "/PE/Sub" or "/Demangler/std"; deeper paths (e.g.
/// "/Demangler/std/ios_base") are not immediate — they belong to the
/// next level down.
///
/// Edge case: parent "/" is treated as the root (so "/PE" is an
/// immediate child of "/", even though we build the prefix as "//"
/// which never matches a real path — handled by the explicit check).
fn is_immediate_child(child_path: &str, parent: &str) -> bool {
    if parent.is_empty() || parent == "/" {
        if !child_path.starts_with('/') {
            return false;
        }
        // Count slashes: "/PE" has 1 (immediate); "/Demangler/std"
        // has 2 (two levels deep — not immediate).
        child_path.matches('/').count() == 1
    } else {
        let prefix = format!("{}/", parent);
        if !child_path.starts_with(&prefix) {
            return false;
        }
        child_path[prefix.len()..].matches('/').count() == 0
    }
}

/// Last path segment of a category path. `/PE` -> "PE";
/// `/Demangler/std` -> "std".
fn last_segment(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, seg)| seg).unwrap_or(path)
}

/// Print one type row at the given prefix (which already includes
/// any connector characters). No newline appended implicitly.
fn print_row(prefix: &str, r: &TypeRow, name_w: usize, kind_w: usize) {
    print!(
        "{}{:<name_w$}  {:<kind_w$}  {:>4}  {}",
        prefix,
        r.name,
        r.kind,
        r.size,
        r.source_label(),
        name_w = name_w,
        kind_w = kind_w
    );
    println!();
}

fn print_show(response: &Json, want_json: bool) -> Result<(), ()> {
    let kind = response.get("kind").and_then(Json::as_str).unwrap_or("?");
    let name = response.get("name").and_then(Json::as_str).unwrap_or("?");
    let path = response.get("path").and_then(Json::as_str).unwrap_or("?");
    let size = response.get("size").and_then(Json::as_f64).unwrap_or(0.0) as i64;

    // --json path: stdout must be VALID JSON ONLY — nothing else. No TSV
    // headline, no `key: value` listing. Dump the whole server response as
    // a single compact JSON object so callers can `jq '.detail'` /
    // `jq '.size'` / `jq '.c'` etc. without any preamble. The previous
    // implementation printed a TSV line first AND then a `key: value`
    // listing — neither was valid JSON, and the leading TSV line was
    // breaking `jq` consumers ("extra content at end of value").
    if want_json {
        // Log status to stderr (not stdout) so the data stream stays
        // pure JSON; agents that only read stdout see only `{...}`.
        log::info!("{} {}\t{}\t{}", name, kind, path, size);
        println!("{}", response);
        return Ok(());
    }

    // Two response shapes share this printer:
    //
    //   * ShowDataType (full): includes `c` (the C declaration) and
    //     `detail` (the structured JSON). Used by `datatype show`.
    //
    //   * ConfirmResponse (lean): NO `c`, NO `detail`. Used by
    //     `datatype create` / `replace` / `edit` to confirm
    //     "I just wrote your type". The confirmation line is the
    //     user's primary feedback — no multi-line C block.
    //
    // The discriminator is the presence of `c`. Lean responses don't
    // have it; full responses always do (even if empty, the absence
    // is the lean signal).
    if response.get("c").is_some() {
        print_show_full(response, name, kind, path, size)
    } else {
        print_confirm(response, name, kind, path, size)
    }
}

/// Full ShowDataType response: TSV headline + multi-line C declaration.
fn print_show_full(
    response: &Json,
    name: &str,
    kind: &str,
    path: &str,
    size: i64,
) -> Result<(), ()> {
    // Headline TSV line: kind<TAB>path<TAB>size. The TSV line is
    // preserved here because it is the one stable piece that
    // scripts pipe to `head -1` or awk on the path.
    println!("{}\t{}\t{}", kind, path, size);

    // C output: require the server-generated `c` field (Ghidra's
    // DataTypeWriter). If it is missing or empty, fail loudly with
    // a non-zero exit — do NOT silently fall back to the JSON
    // detail, because that would re-route output without the user
    // knowing it. The user can rerun with --json to inspect the
    // structured view.
    match response.get("c").and_then(Json::as_str) {
        Some(s) if !s.is_empty() => {
            for line in s.lines() {
                println!("{}", line);
            }
            Ok(())
        }
        _ => Err(common::log_arg_err(format!(
            "server returned no C declaration for '{}' (path={}, kind={}). \
             The C writer did not produce output for this type. \
             Retry with --json to see the structured view.",
            name, path, kind
        ))),
    }
}

/// Lean ConfirmResponse: one line on stdout, no flood.
///
/// Format: `replaced <name> (<kind>, size 0xNN, N fields)` for
/// struct/union; `replaced <name> (<kind>, size 0xNN, N entries)` for
/// enum; `replaced <name> (<kind>, size 0xNN, base=<base>)` for
/// typedef; `replaced <name> (<kind>, size 0xNN)` otherwise.
///
/// The verb (`replaced` vs `created` vs `edited`) is inferred from
/// the response shape: ConfirmResponse has no verb field, so the
/// server returns a `verb` field that the caller set. If absent, we
/// default to "wrote" as a neutral term (matches the printed form
/// on the CLI help text — "I just wrote your type").
fn print_confirm(
    response: &Json,
    name: &str,
    kind: &str,
    path: &str,
    size: i64,
) -> Result<(), ()> {
    // Verb: server sets this to the operation that produced the
    // confirmation ("created", "replaced", "edited"). If the server
    // didn't set it, fall back to a generic verb that doesn't
    // mis-represent any of the three.
    let verb = response
        .get("verb")
        .and_then(Json::as_str)
        .unwrap_or("wrote");

    // Per-kind confirmation. Exactly one of fieldCount/entryCount/base
    // is set in ConfirmResponse; gson omits the others.
    let field_count = response
        .get("fieldCount")
        .and_then(Json::as_f64)
        .map(|n| n as i64);
    let entry_count = response
        .get("entryCount")
        .and_then(Json::as_f64)
        .map(|n| n as i64);
    let base = response.get("base").and_then(Json::as_str);

    // size printed in hex for parity with Ghidra's Type Manager
    // (which always shows struct sizes in hex). 0x0 for zero-size
    // types (e.g. an empty struct with no fields yet).
    let size_hex = format!("0x{:x}", size);

    let mut line = format!("{} {} ({}, size {}", verb, name, kind, size_hex);
    if let Some(n) = field_count {
        let unit = if n == 1 { "field" } else { "fields" };
        line.push_str(&format!(", {} {}", n, unit));
    } else if let Some(n) = entry_count {
        let unit = if n == 1 { "entry" } else { "entries" };
        line.push_str(&format!(", {} {}", n, unit));
    } else if let Some(b) = base {
        line.push_str(&format!(", base={}", b));
    }
    line.push(')');

    // Log a richer diagnostic to stderr for grep parity with the
    // rest of the datatype subcommands. The confirmation line
    // itself goes to stdout (scriptable: `replaced X (struct,
    // size 0xc, 3 fields)` parses trivially).
    log::info!("{} {} {}\t{}\t{}", verb, name, kind, path, size);
    println!("{}", line);
    Ok(())
}

/// Print a SetDataTypeFieldComment response as a small four-line block:
/// `path`, `field`, the new comment (with the previous value in parens
/// for easy diff), and a quiet "cleared" line when the new value is empty.
/// The path/field are also logged to stderr for grep parity with the rest
/// of the datatype subcommands.
fn print_field_comment(response: &Json) -> Result<(), ()> {
    let path = response.get("path").and_then(Json::as_str).unwrap_or("?");
    let field = response.get("field").and_then(Json::as_str).unwrap_or("?");
    let comment = response.get("comment").and_then(Json::as_str);
    let previous = response.get("previous").and_then(Json::as_str);
    log::info!("{} field '{}' comment set", path, field);
    match comment {
        Some(c) if !c.is_empty() => {
            match previous {
                Some(p) if !p.is_empty() && p != c => println!("was:    {}", p),
                _ => {}
            }
            println!("now:    {}", c);
        }
        _ => {
            // Empty / null new comment = cleared.
            match previous {
                Some(p) if !p.is_empty() => println!("cleared (was: {})", p),
                _ => println!("cleared"),
            }
        }
    }
    Ok(())
}

/// Print a SetDataTypeVariantComment response. Same shape as the field
/// helper: path + variant on stderr, then the new/previous value on stdout.
fn print_variant_comment(response: &Json) -> Result<(), ()> {
    let path = response.get("path").and_then(Json::as_str).unwrap_or("?");
    let variant = response
        .get("variant")
        .and_then(Json::as_str)
        .unwrap_or("?");
    let comment = response.get("comment").and_then(Json::as_str);
    let previous = response.get("previous").and_then(Json::as_str);
    log::info!("{} variant '{}' comment set", path, variant);
    match comment {
        Some(c) if !c.is_empty() => {
            match previous {
                Some(p) if !p.is_empty() && p != c => println!("was:    {}", p),
                _ => {}
            }
            println!("now:    {}", c);
        }
        _ => match previous {
            Some(p) if !p.is_empty() => println!("cleared (was: {})", p),
            _ => println!("cleared"),
        },
    }
    Ok(())
}
