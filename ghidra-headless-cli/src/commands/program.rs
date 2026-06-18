//! Project-level commands: import a program, run auto-analysis.

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
        /// Target program project path
        #[arg(long)]
        program: String,
        /// Re-analyze even if already analyzed [default: true]
        #[arg(long)]
        force: Option<bool>,
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
                    .str("program", program)
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
    }
}

fn field_bool(response: &Json, key: &str) -> bool {
    response.get(key).and_then(Json::as_bool).unwrap_or(false)
}

fn field_int(response: &Json, key: &str) -> i64 {
    response.get(key).and_then(Json::as_f64).unwrap_or(0.0) as i64
}
