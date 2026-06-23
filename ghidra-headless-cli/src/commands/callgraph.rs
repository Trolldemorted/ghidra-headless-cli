//! Callgraph subcommand: walk a function's callers or callees up to a
//! depth and return a Mermaid `flowchart` (default) or a structured
//! edges/nodes JSON envelope. Wires to the `Callgraph` RPC procedure.

use clap::Args;

use crate::client::Client;
use crate::json::{Json, Req};

#[derive(Args, Debug)]
pub struct Cmd {
    /// Target file project path
    #[arg(long = "file", value_name = "FILE")]
    pub program: String,
    /// Function name or address to start from
    #[arg(long, value_name = "FN")]
    pub function: String,
    /// Walk direction: called | calling [default: called]
    #[arg(long, value_name = "DIR", default_value = "called")]
    pub direction: String,
    /// Max recursion depth (1..=10) [default: 2]
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub depth: i64,
    /// Output format: mermaid | json [default: mermaid]
    #[arg(long, value_name = "FMT", default_value = "mermaid")]
    pub format: String,
    /// Include non-call references (jump/data refs) [default: false]
    #[arg(long)]
    pub include_refs: Option<bool>,
}

pub fn run(cmd: Cmd, client: &Client) -> Result<(), ()> {
    let response = client.invoke(
        Req::new("Callgraph")
            .str("file", cmd.program)
            .str("function", cmd.function)
            .str("direction", cmd.direction)
            .int("depth", cmd.depth)
            .str("format", cmd.format)
            .opt_bool("includeRefs", cmd.include_refs)
            .build(),
    )?;
    print_callgraph(&response);
    Ok(())
}

fn print_callgraph(response: &Json) {
    let root_name = response
        .get("root")
        .and_then(Json::as_object)
        .and_then(|o| obj_get(o, "name"))
        .and_then(Json::as_str)
        .unwrap_or("?");
    let depth = response.get("depth").and_then(Json::as_f64).unwrap_or(0.0) as i64;
    let truncated = response
        .get("truncated")
        .and_then(Json::as_bool)
        .unwrap_or(false);

    // The response deliberately doesn't carry node/edge counts (they were
    // redundant with the data: Mermaid line count, JSON array length).
    // For Mermaid we count lines by shape; for JSON we read the arrays
    // directly so the log line shows real numbers without re-deriving
    // anything.
    let nodes_arr = response.get("nodes").and_then(Json::as_array);
    let edges_arr = response.get("edges").and_then(Json::as_array);
    let mermaid_str = response.get("mermaid").and_then(Json::as_str);
    let (nc, ec) = match (nodes_arr, edges_arr, mermaid_str) {
        // JSON format: arrays are authoritative.
        (Some(ns), Some(es), _) => (ns.len() as i64, es.len() as i64),
        // Mermaid format: count node defs (`n_xxx["..."]`) and edge
        // arrows (` --> ` or ` -.-> `) line by line.
        (_, _, Some(s)) => count_mermaid(s),
        _ => (0, 0),
    };
    log::info!(
        "callgraph for {} (depth={}, {} nodes, {} edges){}",
        root_name,
        depth,
        nc,
        ec,
        if truncated { " (truncated)" } else { "" }
    );

    // Mermaid format: emit the diagram on stdout so it's pipeable to any
    // Mermaid renderer. JSON format: print the structured nodes/edges.
    if let Some(s) = mermaid_str {
        println!("{}", s);
        return;
    }
    if let Some(nodes) = nodes_arr {
        println!("# nodes ({}):", nodes.len());
        for n in nodes {
            let name = obj_get_pairs(n, "name")
                .and_then(Json::as_str)
                .unwrap_or("?");
            let addr = obj_get_pairs(n, "address")
                .and_then(Json::as_str)
                .unwrap_or("?");
            let d = obj_get_pairs(n, "depth")
                .and_then(Json::as_f64)
                .unwrap_or(0.0) as i64;
            let ext = obj_get_pairs(n, "isExternal")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            let suffix = if ext { " [external]" } else { "" };
            println!("  {} @ {} (depth={}){}", name, addr, d, suffix);
        }
    }
    if let Some(edges) = edges_arr {
        println!("# edges ({}):", edges.len());
        for e in edges {
            let from = obj_get_pairs(e, "from")
                .and_then(Json::as_str)
                .unwrap_or("?");
            let to = obj_get_pairs(e, "to").and_then(Json::as_str).unwrap_or("?");
            let d = obj_get_pairs(e, "depth")
                .and_then(Json::as_f64)
                .unwrap_or(0.0) as i64;
            let rt = obj_get_pairs(e, "refType")
                .and_then(Json::as_str)
                .unwrap_or("?");
            println!("  {} -> {} (depth={}, {})", from, to, d, rt);
        }
    }
}

/// Count nodes and edges in a Mermaid `flowchart` source string. Node
/// lines look like `  n_foo["label"]` (or `n_foo("label")` for rounded);
/// edge lines contain ` --> ` (solid) or ` -.-> ` (dotted). classDef /
/// class lines don't match either.
fn count_mermaid(s: &str) -> (i64, i64) {
    let mut nodes = 0i64;
    let mut edges = 0i64;
    for line in s.lines() {
        let t = line.trim_start();
        if t.contains(" --> ") || t.contains(" -.-> ") {
            edges += 1;
        } else if t.starts_with("n_") && (t.contains('[') || t.contains('(')) {
            // node def — `n_xxx["label"]` or `n_xxx("label")`
            nodes += 1;
        }
    }
    (nodes, edges)
}

/// Look up a key in a `&[(String, Json)]` (the shape of `Json::as_object`).
fn obj_get<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Same as {@link obj_get} but accepting a `&Json` directly (convenient
/// when we already pulled an array entry).
fn obj_get_pairs<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    value.as_object().and_then(|pairs| obj_get(pairs, key))
}
