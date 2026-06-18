//! Data-type management: list / show / create / edit / delete / apply.
//!
//! These wire to the `ListDataTypes`, `ShowDataType`, `CreateDataType`,
//! `EditDataType`, `DeleteDataType`, and `ApplyDataType` RPC procedures.
//!
//! Path syntax mirrors the server: a leading slash, category segments
//! separated by slashes, name as the last segment. Examples: `/int`,
//! `/ELF/Elf64_Ehdr`, `/MyCategory/MyStruct`.
//!
//! Complex payload fields (`--fields` for struct/union, `--entries` for
//! enum) are accepted as JSON literals on the command line. Both are arrays
//! of objects: `[{"name":"x","type":"int"}]` and `[{"name":"RED","value":0}]`.

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
    },
    /// Show a single data type by full path (kind/fields/entries/etc.)
    Show {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Full data-type path, e.g. /ELF/Elf64_Ehdr
        #[arg(long)]
        path: String,
    },
    /// Create a struct / union / enum / typedef
    Create {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// One of: struct, union, enum, typedef
        #[arg(long)]
        kind: String,
        /// New type name (must not already exist in target category)
        #[arg(long)]
        name: String,
        /// Target category path [default: /]
        #[arg(long)]
        category: Option<String>,
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
    /// Edit an existing data type (batched: rename/move/addFields/replaceFields/addEntries)
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
        /// Drop all existing fields before adding (struct/union) [default: false]
        #[arg(long)]
        replace_fields: Option<bool>,
        /// Fields to append (JSON array, struct/union)
        #[arg(long)]
        add_fields: Option<String>,
        /// Entries to append (JSON array, enum)
        #[arg(long)]
        add_entries: Option<String>,
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
    /// Apply a data type at an address (or address range)
    Apply {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Data type to apply (C-syntax expression or full path)
        #[arg(long = "type")]
        type_name: String,
        /// Single address to apply at (hex)
        #[arg(long, conflicts_with = "address_set")]
        address: Option<String>,
        /// Address range as START[:END] (repeatable). When given, --address is ignored.
        #[arg(long = "address-set", value_name = "START[:END]")]
        address_set: Vec<String>,
        /// Byte length to consume at a single address [default: type's length]
        #[arg(long)]
        length: Option<i64>,
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
        } => {
            let response = client.invoke(
                Req::new("ListDataTypes")
                    .str("file", program)
                    .opt_str("category", category)
                    .opt_bool("recursive", recursive)
                    .opt_str("kind", kind)
                    .opt_int("limit", limit)
                    .build(),
            )?;
            print_list(&response);
            Ok(())
        }
        Cmd::Show { program, path } => {
            let response = client.invoke(
                Req::new("ShowDataType")
                    .str("file", program)
                    .str("path", path)
                    .build(),
            )?;
            print_show(&response);
            Ok(())
        }
        Cmd::Create {
            program,
            kind,
            name,
            category,
            fields,
            entries,
            base,
            enum_size,
        } => {
            let fields_json = parse_opt_json("fields", fields)?;
            let entries_json = parse_opt_json("entries", entries)?;
            let response = client.invoke(
                Req::new("CreateDataType")
                    .str("file", program)
                    .str("kind", kind)
                    .str("name", name)
                    .opt_str("category", category)
                    .opt_json("fields", fields_json)
                    .opt_json("entries", entries_json)
                    .opt_str("base", base)
                    .opt_int("enumSize", enum_size)
                    .build(),
            )?;
            print_show(&response);
            Ok(())
        }
        Cmd::Edit {
            program,
            path,
            rename,
            move_to,
            replace_fields,
            add_fields,
            add_entries,
        } => {
            let add_fields_json = parse_opt_json("addFields", add_fields)?;
            let add_entries_json = parse_opt_json("addEntries", add_entries)?;
            let response = client.invoke(
                Req::new("EditDataType")
                    .str("file", program)
                    .str("path", path)
                    .opt_str("rename", rename)
                    .opt_str("move", move_to)
                    .opt_bool("replaceFields", replace_fields)
                    .opt_json("addFields", add_fields_json)
                    .opt_json("addEntries", add_entries_json)
                    .build(),
            )?;
            print_show(&response);
            Ok(())
        }
        Cmd::Delete { program, path } => {
            let response = client.invoke(
                Req::new("DeleteDataType")
                    .str("file", program)
                    .str("path", path)
                    .build(),
            )?;
            let deleted = response.get("deleted").and_then(Json::as_bool).unwrap_or(false);
            log::info!(
                "{} {}",
                if deleted { "deleted" } else { "NOT deleted" },
                response.get("path").and_then(Json::as_str).unwrap_or("?")
            );
            Ok(())
        }
        Cmd::Apply {
            program,
            type_name,
            address,
            address_set,
            length,
        } => {
            let req = Req::new("ApplyDataType")
                .str("file", program)
                .str("type", type_name)
                .opt_int("length", length);
            let req = if !address_set.is_empty() {
                let items: Vec<Json> = address_set
                    .iter()
                    .map(|s| {
                        let parts: Vec<&str> = s.splitn(2, ':').collect();
                        let start = parts[0].to_string();
                        let end = parts.get(1).map(|e| (*e).to_string());
                        let mut fields = vec![("start".to_string(), Json::Str(start))];
                        if let Some(e) = end {
                            fields.push(("end".to_string(), Json::Str(e)));
                        }
                        Json::Obj(fields)
                    })
                    .collect();
                req.opt_json("addressSet", Some(Json::Arr(items)))
            } else {
                req.opt_str("address", address)
            };
            let response = client.invoke(req.build())?;
            let created = response.get("created").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let bytes = response.get("bytes").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            log::info!(
                "applied {} ({} entries, {} bytes)",
                response.get("type").and_then(Json::as_str).unwrap_or("?"),
                created,
                bytes
            );
            Ok(())
        }
    }
}

/// Parse a user-supplied JSON literal (or None) and emit a clear error on
/// malformed input. Used for the `--fields` and `--entries` arrays.
fn parse_opt_json(name: &str, value: Option<String>) -> Result<Option<Json>, ()> {
    match value {
        None => Ok(None),
        Some(text) => Json::parse(&text)
            .map(Some)
            .map_err(|e| common::log_arg_err(format!("invalid JSON for --{}: {}", name, e))),
    }
}

fn print_list(response: &Json) {
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response.get("truncated").and_then(Json::as_bool).unwrap_or(false);
    log::info!(
        "found {} type{}{}",
        count,
        if count == 1 { "" } else { "s" },
        if truncated { " (truncated by limit)" } else { "" }
    );
    if let Some(arr) = response.get("types").and_then(Json::as_array) {
        for t in arr {
            let name = t.get("name").and_then(Json::as_str).unwrap_or("?");
            let kind = t.get("kind").and_then(Json::as_str).unwrap_or("?");
            let size = t.get("size").and_then(Json::as_f64).unwrap_or(0.0) as i64;
            let src = t.get("source").and_then(Json::as_str).unwrap_or("");
            println!("{}\t{}\t{}\t{}", name, kind, size, src);
        }
    }
}

fn print_show(response: &Json) {
    log::info!(
        "{} {} ({})",
        response.get("kind").and_then(Json::as_str).unwrap_or("?"),
        response.get("path").and_then(Json::as_str).unwrap_or("?"),
        response.get("size").and_then(Json::as_f64).unwrap_or(0.0) as i64,
    );
    if let Some(detail) = response.get("detail").and_then(Json::as_object) {
        for (key, value) in detail {
            println!("{}: {}", key, scalar_or_inline(value));
        }
    }
}

/// Render a JSON value as a one-line summary suitable for `key: value` listing.
/// Arrays/objects are kept on one line (compact JSON) so the listing stays scannable.
fn scalar_or_inline(value: &Json) -> String {
    match value {
        Json::Str(s) => s.clone(),
        Json::Num(n) => {
            if n.is_finite() && n.fract() == 0.0 {
                (*n as i64).to_string()
            } else {
                n.to_string()
            }
        }
        Json::Bool(b) => b.to_string(),
        Json::Null => "null".to_string(),
        other => other.to_string(),
    }
}
