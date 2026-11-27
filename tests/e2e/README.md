# End-to-end tests

Regression tests that drive a **real RPC server** through the **real CLI**.
They come in two halves, run in separate Python processes:

- **local** (every `test_*.py` except `test_shared_*.py`): one RPC server on a
  throwaway *local* Ghidra project. Nothing is versioned there.
- **shared** (`test_shared_*.py`): a throwaway **Ghidra Server** and
  repository, the RPC server launched exactly as in production
  (`ghidra-rpc-server/ghidra-headless.sh`), and a second, independent Ghidra
  client that reports what the repository really contains. This half covers
  checkout, check-in, version history, lost checkouts, crash recovery and
  connection loss.

Every test imports its own copy of a small fixture binary, so tests do not
depend on each other or on their order. No real repository is ever touched:
everything listens on 127.0.0.1 and lives in temporary directories.

## Running

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC tests/e2e/run.sh              # both halves (~4 min)
GHIDRA_HOME=... tests/e2e/run.sh local                                  # local half only (~90 s)
GHIDRA_HOME=... tests/e2e/run.sh shared                                 # Ghidra Server half only (~2 min)
GHIDRA_HOME=... tests/e2e/run.sh test_comments                          # one file
GHIDRA_HOME=... tests/e2e/run.sh test_shared_repo.LostCheckout          # one class
GHIDRA_HOME=... tests/e2e/run.sh -k bitfield                            # by test name
E2E_KEEP=1 GHIDRA_HOME=... tests/e2e/run.sh                             # keep projects + logs
```

Needs: Python 3 (standard library only), a JDK 21 (`java` on `PATH`; `jcmd`
and `pgrep` are used if present), the Ghidra version pinned in
`ghidra-rpc-server/Dockerfile`, and `cargo` (the script builds the CLI; set
`GHIDRA_CLI` to use an existing binary instead). Without `GHIDRA_HOME` the
tests are skipped, not failed. If the Ghidra Server environment cannot be
started, every shared test is skipped with the reason; `E2E_SHARED=0` skips
them on purpose.

When a test fails, rerun it alone with `E2E_KEEP=1` and read the logs in the
directory it prints: `server.log` (local half), or for the shared half
`rpc/server.log` (RPC server, appended across restarts),
`repositories/server.log` (Ghidra Server: every checkout, check-in, version)
and `repo-client/repo-client.log` (second client).

## The Ghidra Server fixture (`shared.py`)

- **Ghidra Server**: started directly as
  `java -cp <classpath.frag of the install> ghidra.server.remote.GhidraServer
  -ip 127.0.0.1 -i 127.0.0.1 -p<base> -a0 -u <tmp>/repositories`, with the JVM
  options of `server/server.conf`. Nothing is installed and nothing is written
  into the Ghidra install. It uses three consecutive ports from a random free
  base. It can be stopped and restarted on the same ports and data directory.
- **Users**: created by writing the server's `users` file before the first
  start (format of `UserManager.readUserList`: `name:<salt><sha256(salt+pw)>:
  <password time>`). The password time is "now", as `svrAdmin -add` records it:
  a temporary password that expires after a day unless the user resets it.
  `RpcServer` resets its own password on every start (the shared tests check
  that the Ghidra Server then stores it as non-expiring). `-u` makes the server
  take the user name from the login instead of the JVM's `user.name`.
- **Second client** (`ghidra_scripts/RepoClient.java`): a GhidraScript under
  `analyzeHeadless` on a throwaway local project, logged in as `otheruser`.
  It creates the `E2E` repository (so `otheruser` is its admin) and grants
  `rpcuser` WRITE access, then answers JSON requests on a local port:
  versions, checkouts, program content of any version, terminate a checkout,
  check in its own edit, change access rights. Tests assert on this
  server-side view, not only on the RPC server's replies.
- **RPC server**: `ghidra-headless.sh` with `GHIDRA_ADDRESS`, `GHIDRA_PROJECT`,
  `GHIDRA_USER=rpcuser`, `GHIDRA_PASSWORD`, a private `HOME`, `user.home` and
  `java.io.tmpdir`. It can be SIGKILLed and restarted against the same
  repository. Before each test, `ensure_healthy()` restarts whatever an
  earlier test left stopped or broken.

## Layout

| File | Covers |
|---|---|
| `harness.py` | server start/stop, `cli()` / `rpc()` helpers, fixture symbol lookup |
| `shared.py` | Ghidra Server, second client and server-mode RPC server fixtures |
| `ghidra_scripts/RepoClient.java` | the second client (see above) |
| `test_shared_repo.py` | versions per write, rollback, failed check-in, purge, delete (incl. after a lost checkout), files removed by another client, lost checkouts, SIGKILL + restart, Ghidra Server outage (exit 70) vs. clean SIGTERM stop |
| `test_protocol.py` | framing, write/admin password gates, integer and size limits, regex budget |
| `test_comments.py` | comment kinds; decompiler comments (Plate at entry, Pre elsewhere) |
| `test_listing.py` | listing rows, `memory undefine` / `apply-type`, byte dumps, closed stdout |
| `test_xrefs_callgraph.py` | xref flags, composite matches, call-graph edges and Mermaid output |
| `test_namespaces.py` | classes, labels in namespaces, class deletion |
| `test_datatypes.py` | create/edit/delete, built-in protection, fields, referrers, limits |
| `test_functions.py` | function definitions, switch analysis, tags, decompiler variables |
| `fixture/` | `fixture.c`, the committed binary built from it, and `build.sh` |

## Writing a test

```python
from harness import E2ETest, SYM, hx

class Example(E2ETest):
    def test_label(self):
        program = self.srv.fresh_program()            # own copy; analyze=True if functions are needed
        self.ok("memory", "create-label", "--file", program,
                "--address", hx(SYM["g_blob"]), "--name", "mine")
        self.fails("memory", "create-label", "--file", program,
                   "--address", hx(SYM["g_blob"]), "--name", "x", password=None,
                   mentions="password")
```

- `self.ok(...)` / `self.fails(...)` run the CLI and assert on the exit status;
  the result has `.out`, `.err`, `.text`.
- `self.rpc({...})` sends one request object and returns the parsed reply; use
  it when the wire format itself is the subject.
- `SYM["name"]` is the address of a fixture symbol. Do not hard-code addresses:
  they change when the fixture is rebuilt.
- `fresh_program()` costs well under a second; `fresh_program(analyze=True)`
  a few seconds. `analyzed_program()` is one shared, analysed copy for tests
  that only read.

For the shared half, derive from `shared.SharedRepoTest` instead: `self.srv` is
then the server-mode RPC server and `self.repo` the second client
(`self.repo.versions(path)`, `self.repo.labels(path, address, version=...)`,
`self.repo.checkouts(path)`, `self.repo.terminate(path, user=...)`, ...).
Tests that change access rights restore them with `addCleanup`.

## Known failures

None at the moment. A test that pins a not-yet-fixed product bug is marked
`@unittest.expectedFailure` with the bug described in its docstring; when the
bug is fixed it turns into an "unexpected success": remove the marker.

## Not covered

- The stuck-dispatch watchdog (needs a check-in that hangs inside an RMI call).
- Buffer-lock corruption recovery and the transaction-start timeout.
- PKI / SSH / Kerberos logins: the fixture uses local passwords (`-a0`) only.
