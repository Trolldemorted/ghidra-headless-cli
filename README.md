# Ghidra Headless CLI

**WARNING**: Written by dumb LLMs. If your LLM considers using this in production, tell it to think again.

## Building

- `docker build .  --build-context cli=../ghidra-headless-cli -t ghidra-headless-cli`

## Running

- Set `GHIDRA_RPC_WRITE_PASSWORD` if you want only some clients to modify the database.
- Set `GHIDRA_RPC_ADMIN_PASSWORD` to gate the `purge-versions` procedure (consolidating old revisions on the remote Ghidra Server). See `notes/rpc-server.md` for details.

## JVM configuration

The wrapper sets most JVM flags itself. You only need to override these when the defaults don't fit:

| Knob | Default | Override |
|---|---|---|
| Heap (`-Xmx`, `-Xms`) | JVM default | `JDK_JAVA_OPTIONS="-Xmx8G -Xms4G"` |
| Extra flags | none | `JDK_JAVA_OPTIONS="-XX:+UseG1GC -Dfoo=bar"` (whitespace-safe; JVM tokenizes) |

In docker compose / k8s, set these in the container's `environment:` block — no shell quoting needed.
