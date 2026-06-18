//! Project file operations: import a program, run auto-analysis.

use std::fs;

use clap::Subcommand;

use crate::client::Client;
use crate::common;
use crate::json::{Json, Req};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Import a new program into the project from a local file
    Load {
        /// Program name to create in the project, e.g. "foo.exe"
        #[arg(long)]
        name: String,
        /// Local file whose bytes are uploaded (base64-encoded in the request)
        #[arg(long)]
        file: String,
        /// Destination project folder; created if missing [default: /]
        #[arg(long)]
        folder: Option<String>,
        /// Version-control comment [default: none]
        #[arg(long)]
        comment: Option<String>,
    },
    /// Run full auto-analysis over a program
    Analyze {
        /// Target file project path
        #[arg(long = "file", value_name = "FILE")]
        program: String,
        /// Re-analyze even if already analyzed [default: true]
        #[arg(long)]
        force: Option<bool>,
    },
    /// List project files under a folder
    List {
        /// Folder to list [default: /]
        #[arg(long)]
        folder: Option<String>,
        /// Recurse into subfolders [default: true]
        #[arg(long)]
        recursive: Option<bool>,
        /// Include folder entries in the output [default: false]
        #[arg(long)]
        include_folders: Option<bool>,
        /// Keep only files of this content type, e.g. "Program" [default: all]
        #[arg(long)]
        content_type: Option<String>,
        /// Cap the number of results [default: 0 = unlimited]
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Show a project file's attributes and stored metadata
    Metadata {
        /// Target file project path
        #[arg(long)]
        file: String,
    },
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    match cmd {
        Cmd::Load {
            name,
            file,
            folder,
            comment,
        } => {
            let bytes = fs::read(&file)
                .map_err(|e| common::log_arg_err(format!("read {}: {}", file, e)))?;
            let response = client.invoke(
                Req::new("ProgramLoader")
                    .str("name", name)
                    .str("bytes", common::base64_encode(&bytes))
                    .opt_str("folder", folder)
                    .opt_str("comment", comment)
                    .build(),
            )?;
            if let Some(imported) = response.get("imported").and_then(Json::as_array) {
                for path in imported.iter().filter_map(Json::as_str) {
                    log::info!("imported {}", path);
                }
            }
            let primary = response.get("primary").and_then(Json::as_str).unwrap_or("?");
            let format = response.get("format").and_then(Json::as_str).unwrap_or("?");
            log::info!("primary {} ({})", primary, format);
            Ok(())
        }
        Cmd::Analyze { program, force } => {
            let response = client.invoke(
                Req::new("Analyze")
                    .str("file", program)
                    .opt_bool("force", force)
                    .build(),
            )?;
            let analyzed = field_bool(&response, "analyzed");
            let was_analyzed = field_bool(&response, "wasAnalyzed");
            let function_count = field_int(&response, "functionCount");
            let symbol_count = field_int(&response, "symbolCount");
            let format = response.get("format").and_then(Json::as_str).unwrap_or("?");
            log::info!(
                "analyzed={} wasAnalyzed={} functions={} symbols={} format={}",
                analyzed,
                was_analyzed,
                function_count,
                symbol_count,
                format
            );
            Ok(())
        }
        Cmd::List {
            folder,
            recursive,
            include_folders,
            content_type,
            limit,
        } => {
            let response = client.invoke(
                Req::new("ListFiles")
                    .opt_str("folder", folder)
                    .opt_bool("recursive", recursive)
                    .opt_bool("includeFolders", include_folders)
                    .opt_str("contentType", content_type)
                    .opt_int("limit", limit)
                    .build(),
            )?;
            print_listing(&response);
            Ok(())
        }
        Cmd::Metadata { file } => {
            let response = client.invoke(Req::new("FileMetadata").str("file", file).build())?;
            print_metadata(&response);
            Ok(())
        }
    }
}

/// Print one entry per line on stdout: folders as `<path>/`, files as
/// `<path>  <contentType>  v<version>` (with a `[checked-out]` marker), count to stderr.
fn print_listing(response: &Json) {
    let count = response.get("count").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    log::info!(
        "found {} entr{}{}",
        count,
        if count == 1 { "y" } else { "ies" },
        if truncated { " (truncated by limit)" } else { "" }
    );

    if let Some(files) = response.get("files").and_then(Json::as_array) {
        for f in files {
            let path = f.get("path").and_then(Json::as_str).unwrap_or("");
            if f.get("isFolder").and_then(Json::as_bool).unwrap_or(false) {
                println!("{}/", path);
            } else {
                let content_type = f.get("contentType").and_then(Json::as_str).unwrap_or("");
                let version = f.get("version").and_then(Json::as_f64).unwrap_or(0.0) as i64;
                let checked_out = f.get("checkedOut").and_then(Json::as_bool).unwrap_or(false);
                println!(
                    "{}  {}  v{}{}",
                    path,
                    content_type,
                    version,
                    if checked_out { "  [checked-out]" } else { "" }
                );
            }
        }
    }
}

/// Print a file's attributes followed by its stored metadata map, to stdout.
fn print_metadata(response: &Json) {
    log::info!(
        "metadata for {}",
        response.get("name").and_then(Json::as_str).unwrap_or("?")
    );
    for key in [
        "path",
        "name",
        "contentType",
        "version",
        "versioned",
        "checkedOut",
        "readOnly",
        "size",
        "lastModified",
        "fileID",
    ] {
        if let Some(value) = response.get(key) {
            println!("{}: {}", key, scalar(value));
        }
    }
    if let Some(metadata) = response.get("metadata").and_then(Json::as_object) {
        if !metadata.is_empty() {
            println!("metadata:");
        }
        for (key, value) in metadata {
            println!("  {}: {}", key, scalar(value));
        }
    }
}

/// Render a JSON scalar (string, bool, or number) as a plain display string.
fn scalar(value: &Json) -> String {
    if let Some(s) = value.as_str() {
        s.to_string()
    } else if let Some(b) = value.as_bool() {
        b.to_string()
    } else if let Some(n) = value.as_f64() {
        if n.fract() == 0.0 {
            (n as i64).to_string()
        } else {
            n.to_string()
        }
    } else {
        String::new()
    }
}

fn field_bool(response: &Json, key: &str) -> bool {
    response.get(key).and_then(Json::as_bool).unwrap_or(false)
}

fn field_int(response: &Json, key: &str) -> i64 {
    response.get(key).and_then(Json::as_f64).unwrap_or(0.0) as i64
}
