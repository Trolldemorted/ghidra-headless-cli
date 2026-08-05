# Ghidra Headless CLI

**WARNING**: Written by dumb LLMs. If your LLM considers using this in production, tell it to think again.

## Building

- `docker build .  --build-context cli=../ghidra-headless-cli -t ghidra-headless-cli`

## Running

- Set `GHIDRA_RPC_WRITE_PASSWORD` if you want only some clients to modify the database.

## JVM tuning (`ghidra-headless.sh` → `java`)

The wrapper bypasses upstream `support/analyzeHeadless` + `support/launch.sh` + `support/launch.properties` entirely. All JVM args come from env vars; new flags go in `ghidra-headless.sh`'s `JDK_JAVA_OPTIONS` block.

| Knob | How |
|---|---|
| Heap (`-Xmx`) | `GHIDRA_HEADLESS_MAXMEM=8G ./ghidra-headless.sh …` |
| Append a flag | `JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS -XX:+UseG1GC" ./ghidra-headless.sh …`. Tokens survive whitespace (JVM tokenizes, not bash). |
| Per-invocation escape hatch | `GHIDRA_HEADLESS_JAVA_OPTIONS="…" ./ghidra-headless.sh …` — folded into `JDK_JAVA_OPTIONS`. |
| Locale / `user.name` / `-Djava.system.class.loader` | set in `_JAVA_OPTIONS` (env-var, JVM-init phase); see `ghidra-headless.sh`. |
