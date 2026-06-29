# Ghidra Headless CLI

**WARNING**: Written by dumb LLMs. If your LLM considers using this in production, tell it to think again.

## Building

- `docker build .  --build-context cli=../ghidra-headless-cli -t ghidra-headless-cli`

## Running

- Set `GHIDRA_RPC_WRITE_PASSWORD` if you want only some clients to modify the database.
