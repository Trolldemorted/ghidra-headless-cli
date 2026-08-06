# Ghidra Headless CLI

**WARNING**: Written by dumb LLMs. If your LLM considers using this in production, tell it to think again.

## Building

- `docker build .  --build-context cli=../ghidra-headless-cli -t ghidra-headless-cli`

## Running

The wrapper needs four env vars to authenticate against the Ghidra Server:

| Var | Purpose | Example |
|---|---|---|
| `GHIDRA_ADDRESS` | server host[:port] | `ghidra.stronk.pw` or `host:13100` |
| `GHIDRA_PROJECT` | repository name | `P3` |
| `GHIDRA_USER` | login user | `claude` |
| `GHIDRA_PASSWORD` | login password | (your password; forwarded into the JVM as an env var, never as `-D`) |

Plus two optional RPC-server gates:

- `GHIDRA_RPC_WRITE_PASSWORD` — if set, write requests must carry `writePassword`. See `notes/rpc-server.md`.
- `GHIDRA_RPC_ADMIN_PASSWORD` — gates the `purge-versions` procedure (consolidating old revisions on the Ghidra Server). See `notes/rpc-server.md`.

Full env-var list (folder, program, script, readonly, etc.) lives in `ghidra-headless.sh`'s header comment.

## JVM configuration

The wrapper sets most JVM flags itself. You only need to override these when the defaults don't fit:

| Knob | Default | Override |
|---|---|---|
| Heap (`-Xmx`, `-Xms`) | JVM default | `JDK_JAVA_OPTIONS="-Xmx8G -Xms4G"` |
| Extra flags | none | `JDK_JAVA_OPTIONS="-XX:+UseG1GC -Dfoo=bar"` (whitespace-safe; JVM tokenizes) |

In docker compose / k8s, set these in the container's `environment:` block — no shell quoting needed.
