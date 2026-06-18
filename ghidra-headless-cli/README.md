# ghidra-headless-cli

Synchronous, dependency-light Rust CLI for the Ghidra TCP ndjson RPC server.
Subcommands mirror the server's 39 procedures, grouped by area
(`function` — with `function decompile` and function tags under `function tag` —
`variable`, `stack`, `analysis`, `datatype`, `program`).

Build:

```bash
export RUSTUP_HOME=/workdir/.rustup CARGO_HOME=/workdir/.cargo PATH=/workdir/.cargo/bin:$PATH
cargo build --release
./target/release/ghidra-headless-cli --help
```

Full documentation — subcommand→procedure table, argument conventions, output
and exit-code semantics, and examples — is in
[`/workdir/notes/cli.md`](../notes/cli.md). Per-procedure request/response
specs are in `/workdir/notes/procedures/`.
