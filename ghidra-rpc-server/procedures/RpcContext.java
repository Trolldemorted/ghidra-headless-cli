package procedures;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import procedures.ghidra.program.model.data.DataTypeOps;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.task.TaskMonitor;

/**
 * Per-server shared context + helper layer handed to every procedure.
 *
 * PROGRAM SELECTION: the server is not bound to a single program. Every
 * program-related procedure (see {@link RpcProcedure#needsProgram()}) carries a
 * mandatory {@code "file"} field — the target's project path (e.g.
 * {@code "/Mapeditor.exe"}). {@link #dispatch} resolves it once per request via
 * {@link #openProgram}, opening (and caching) the program from the project, and stores
 * it as the request's {@linkplain #active() active program}. All resolvers
 * ({@link #requireAddress}, {@link #requireFunctionAt}, {@link #applyCommand}, ...)
 * operate on that active program, so the procedure handlers never name it explicitly.
 *
 * SYNCHRONIZATION: a single {@link #lock} (ReentrantLock) serializes the ENTIRE
 * lifecycle of every request — program resolution, checkout, the procedure's mutation,
 * and the check-in — because Ghidra's program database is not safe for concurrent
 * mutation. {@link #dispatch} holds the lock from before {@link #openProgram} until
 * after check-in, so resolution+mutation+push are atomic with respect to other clients;
 * no other client can interleave a read or write in between. The lock is reentrant so a
 * procedure may call {@link #runWrite}/{@link #applyCommand} (which open program
 * transactions) without deadlock. The per-request {@link #active} field is only ever
 * read or written by the lock-holding thread inside the locked region, so it needs no
 * separate guard. The open-program cache is likewise only touched under the lock.
 */
public class RpcContext {

    private final Project project;
    private final TaskMonitor monitor;

    /**
     * Max number of distinct programs kept open concurrently. LRU eviction past
     * this threshold: the eldest clean (non-dirty) entry is released, freeing
     * its {@code BufferMgr} + listing cache + analyzer state. The exclusive
     * checkout lives on the {@link DomainFile} (server-side), not on the
     * {@link Program}, so {@link Program#release release} during eviction does
     * NOT orphan the checkout. Sized for a healthy multi-binary workflow
     * (single project, dozens of binaries) while bounding long-running server
     * heap — without this, the cache grew unboundedly across every distinct
     * program the server had ever touched.
     *
     * <p>Dirty programs pin a slot rather than risk silent data loss: an
     * evict-during-rename would dispose the BufferMgr holding the in-flight
     * mutation, dropping the user's edit on the floor. The lock serializes
     * requests, so the dirty-set is bounded in practice by failed-checkin
     * churn, not by concurrent mutations.
     */
    private static final int MAX_OPEN_PROGRAMS = 50;

    /**
     * Open programs by canonical project path, access-ordered (LRU). Guarded by
     * {@link #lock}. On insert past {@link #MAX_OPEN_PROGRAMS} the eldest
     * clean entry is released and dropped — see the {@link
     * LinkedHashMap#removeEldestEntry} override below for the dirty-program
     * guard.
     */
    private final Map<String, Program> open = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Program> eldest) {
            if (size() <= MAX_OPEN_PROGRAMS) {
                return false;
            }
            // Pin dirty programs (see MAX_OPEN_PROGRAMS Javadoc). Re-checked
            // on every eviction — once the program saves+checkins cleanly,
            // isChanged() flips false and the next eviction wave releases it.
            Program p = eldest.getValue();
            if (p.isChanged()) {
                return false;
            }
            try {
                p.release(RpcContext.this);
            } catch (Exception ignored) {
                // best-effort; release is idempotent and the server-side
                // checkout is unaffected (the DomainFile, not the Program, owns it).
            }
            return true;
        }
    };

    /**
     * Callback invoked when a write to the Ghidra Server surfaces "Not connected
     * to repository server" — the RMI connection has died mid-session. The
     * callback should arrange for the JVM to exit so an external orchestrator
     * (compose / k8s / systemd) can restart us. Reconnecting a parked JVM to a
     * live Ghidra Server is non-trivial (the cached {@link Project} is bound to
     * the dead RMI connection, and re-authenticating mid-session is not a
     * documented Ghidra flow), so a clean restart is the simplest correct
     * recovery for now. Null until {@link #onConnectionLost(Runnable)} wires one
     * up. Set rarely, fired rarely; volatile suffices.
     */
    private volatile Runnable onConnectionLost;

    /**
     * Consecutive {@code "Not connected to repository server"} checkin failures
     * before {@link #onConnectionLost} fires. A short TCP blip usually produces
     * 1-2 such errors before recovery (TCP retransmits handle in-flight calls;
     * the next new call after the blip succeeds). Sustained outages produce
     * many in a row — that's the regime where an orchestrator-driven restart
     * is the right move. Read &amp; written only inside {@link #lock} (dispatch
     * holds the lock across checkin), so no extra synchronization needed.
     */
    private static final int CONNECTION_LOST_THRESHOLD = 5;

    /** Consecutive connection-lost checkin failures since the last successful checkin. */
    private int connectionLostFailures = 0;

    /**
     * Register a handler that fires when {@link #checkin} detects the underlying
     * Ghidra Server connection has been lost. Only one handler at a time;
     * passing a new one replaces the previous. Pass null to clear. Called from
     * the server's main thread at startup; invoked from an rpc-client thread
     * inside the request lock when checkin hits the disconnect signature.
     */
    public void onConnectionLost(Runnable handler) {
        this.onConnectionLost = handler;
    }

    /** The program selected for the in-flight request; set/cleared by {@link #dispatch} under {@link #lock}. */
    private Program active;

    /**
     * Transaction id of the dispatch-owned transaction on the active program,
     * or {@code -1} if none is open. For mutating procedures, {@link #dispatch}
     * opens the transaction itself and holds it open across the checkin
     * attempt so a failed push can roll back the in-memory state. Read &
     * written only inside {@link #lock} (dispatch holds the lock across the
     * entire request lifecycle, including the checkin).
     *
     * <p>Re-opened after a buffer-lock corruption recovery
     * ({@link #evictAndReopen}) because the old {@link Program} is released —
     * Ghidra implicitly aborts the old transaction on release, and the new
     * program needs a fresh tx.
     */
    private int dispatchTxId = -1;

    /**
     * Files whose most recent {@link #checkin} failed and whose local on-disk
     * copy may now diverge from the Ghidra Server. {@link #closeAll} and the
     * server startup hook call {@link #revertDirtyLocalFiles} to bring the
     * local state back in line with the server. Read &amp; written only
     * inside {@link #lock} (dispatch holds the lock across checkin, so this
     * set is touched only by the request thread). Identity-based set
     * ({@link DomainFile} has no stable equals/hashCode contract) so we use
     * a {@link HashSet} and operate on the exact reference the live program
     * is bound to.
     */
    private final Set<DomainFile> dirtyLocalFiles = new HashSet<>();

    /** Serializes the whole request lifecycle (see class doc). Reentrant for nested runWrite. */
    private final ReentrantLock lock = new ReentrantLock();

    /**
     * Create a context bound to {@code project} with ZERO open programs. The server starts
     * empty: every program is opened on demand by {@link #openProgram} when a request names
     * it. The program analyzeHeadless processed to invoke this script is only a trigger and
     * is intentionally NOT seeded here (see RpcServer).
     */
    public RpcContext(Project project, TaskMonitor monitor) {
        this.project = project;
        this.monitor = monitor;
    }

    /** The program selected for the current request; throws if none is active. */
    public Program program() {
        return active();
    }

    private Program active() {
        Program p = active;
        if (p == null) {
            throw new IllegalStateException("No program is selected for this request.");
        }
        return p;
    }

    public TaskMonitor monitor() {
        return monitor;
    }

    /** The project the server is bound to; for project-level procedures (e.g. import). */
    public Project project() {
        return project;
    }

    /**
     * Resolve a project path (or bare name, like program resolution) to its
     * {@link DomainFile}. Unlike {@link #program()} this does NOT open or check out the
     * file — it inspects the project tree only, so it works for any content type and any
     * file regardless of checkout state. Throws {@link IllegalArgumentException} if the
     * project is unavailable or no such file exists.
     */
    public DomainFile requireDomainFile(String path) {
        if (project == null) {
            throw new IllegalArgumentException(
                "No project is available; cannot select file '" + path + "'.");
        }
        java.util.List<String> candidates = new java.util.ArrayList<>();
        DomainFile df = resolveFile(path, candidates);
        if (df == null) {
            throw new IllegalArgumentException(noFileMessage(path, candidates));
        }
        return df;
    }

    // ---------------------------------------------------------------------------
    // Dispatch: select program -> checkout -> execute -> (if mutating) checkin,
    // all under one lock.
    // ---------------------------------------------------------------------------

    /**
     * Run a procedure with exclusive program access. Holds {@link #lock} across the
     * whole sequence so program selection, checkout, mutation and check-in cannot
     * interleave with other clients. For program-related procedures the mandatory
     * {@code "file"} field selects the target; per policy the file is checked out
     * first and every successful mutating procedure is checked in immediately (the call
     * fails if the push fails).
     *
     * <p><b>No default file.</b> Program-targeting procedures MUST supply an
     * explicit {@code "file"} field. The dispatcher NEVER picks a fallback
     * program from the project (e.g. "the first one") when {@code "file"} is
     * missing or empty — that would silently mutate an unintended program
     * when the user forgot the flag. The error returned is
     * {@code "Missing required field 'file'."} so the CLI can surface it
     * verbatim; clap's required-arg handling on the CLI side produces the
     * same message before the request even reaches the server. This is a
     * deliberate defense-in-depth: server-side validation here protects raw
     * ndjson callers that bypass the CLI.
     */
    public RpcResponse dispatch(RpcProcedure procedure, JsonObject request) throws Exception {
        lock.lock();
        try {
            // Capture path up front so the corruption-recovery retry (below) can re-resolve
            // the DomainFile. Only set when the procedure targets a program.
            String path = procedure.needsProgram() ? optStr(request, "file") : null;
            if (procedure.needsProgram() && (path == null || path.isEmpty())) {
                return RpcResponse.error("Missing required field 'file'.");
            }
            Program program = null;
            if (path != null) {
                try {
                    program = openProgram(path); // checks the file out before opening it
                } catch (Exception e) {
                    return RpcResponse.error(message(e));
                }
            }
            active = program;
            // For mutating procedures, dispatch owns the transaction and holds
            // it open across the checkin attempt so a failed push can roll
            // back the in-memory state — the CLI's contract is "non-zero exit
            // means the change did NOT land". Read-only procedures don't open
            // a tx here (they don't need one and runWrite isn't on their path).
            boolean dispatchOwnsTx = procedure.mutates() && program != null;
            if (dispatchOwnsTx) {
                dispatchTxId = program.startTransaction("RPC " + procedureOf(request));
            }
            // Whether the dispatch-owned tx has been finalized (commit/rollback)
            // yet — drives the finally's defensive rollback if a throw bypassed
            // the explicit endTransaction call.
            boolean txFinalized = false;
            try {
                RpcResponse response = null;
                boolean recovered = false; // exactly one retry per request
                // 1st attempt (or the retry after recovery): may throw or return a response.
                try {
                    response = procedure.execute(request, this);
                } catch (Exception primaryEx) {
                    if (!recovered && program != null && isBufferLockError(primaryEx)) {
                        // Thrown-buffer-lock surface (e.g. "Locked buffer: N" escapes the
                        // decompiler subprocess): evict + retry once.
                        logBufferLockRecovery(procedureOf(request), message(primaryEx));
                        try {
                            program = evictAndReopen(path);
                        } catch (Exception reopenEx) {
                            return RpcResponse.error("Recovery reopen failed after "
                                + "buffer-lock corruption: " + message(reopenEx));
                        }
                        active = program;
                        recovered = true;
                        // The old program was released; Ghidra implicitly aborts
                        // its open transactions. Start a fresh dispatch tx on
                        // the new program so runWrite's dispatchOwnedTransaction
                        // check correctly sees the open tx.
                        if (dispatchOwnsTx) {
                            dispatchTxId = program.startTransaction("RPC " + procedureOf(request));
                        }
                        try {
                            response = procedure.execute(request, this);
                        } catch (Exception retryEx) {
                            // Retry also threw. Re-throw so the caller sees a real error;
                            // the recovery already logged the WARN above.
                            throw retryEx;
                        }
                    } else {
                        throw primaryEx;
                    }
                }
                // 2nd surface: the command returns false with a status message like
                // "Can't checkpoint with locked buffers (N locks found)" rather than
                // throwing — see the original traceback. Same eviction + retry, gated
                // by the `recovered` flag so we never loop.
                if (!recovered && program != null && response != null && !response.success
                        && isBufferLockError(response.error)) {
                    logBufferLockRecovery(procedureOf(request), response.error);
                    try {
                        program = evictAndReopen(path);
                    } catch (Exception reopenEx) {
                        return RpcResponse.error("Recovery reopen failed after "
                            + "buffer-lock corruption: " + message(reopenEx));
                    }
                    active = program;
                    recovered = true;
                    if (dispatchOwnsTx) {
                        dispatchTxId = program.startTransaction("RPC " + procedureOf(request));
                    }
                    response = procedure.execute(request, this);
                }
                // Commit the dispatch-owned tx BEFORE checkin(). save() (called
                // from df.checkin via DomainObjectAdapterDB.save) requires no
                // open tx — DomainObjectAdapterDB.lock("save") throws
                // IOException("Unable to lock due to active transaction") if
                // any tx is open on the same DB handle (verified in
                // Framework/Project/data/DomainObjectAdapterDB.save).
                //
                // Trade-off: a failed checkin now leaves the change committed
                // in-memory, so the next request on this JVM sees it. The
                // cross-JVM divergence is caught by Phase 2 (checkin's catch
                // block already calls markDirty) + Phase 3 (revertDirtyLocalFiles
                // on the next JVM startup undoes the checkout). The in-JVM
                // rollback is sacrificed — acceptable because the same tx
                // already applied to the cached Program's buffer data is
                // visually benign until that Program is closed.
                if (response != null && response.success && dispatchOwnsTx && !txFinalized) {
                    program.endTransaction(dispatchTxId, true);
                    txFinalized = true;
                }
                if (response != null && response.success && procedure.mutates() && program != null) {
                    RpcResponse checkinError = checkin(program, procedureOf(request));
                    if (checkinError != null) {
                        // Push failed. The change is already committed
                        // in-memory above (commit-before-checkin). save()
                        // may have landed partial bytes before checkin threw;
                        // checkin()'s catch path calls markDirty(program),
                        // and revertDirtyLocalFiles() at next JVM startup
                        // will undoCheckout the divergent local file. We do
                        // NOT roll back the in-memory state here — the
                        // cached Program keeps the change visible to
                        // subsequent RPC calls until that Program is closed.
                        response = checkinError;
                    }
                }
                return response;
            } catch (Exception e) {
                // Handler threw (not the checkin-failure branch above). The tx
                // is still open; roll back so the next request on this program
                // doesn't see a partial in-memory mutation.
                if (dispatchOwnsTx && !txFinalized) {
                    try {
                        program.endTransaction(dispatchTxId, false);
                    } catch (Exception ignored) {
                        // best-effort; Ghidra will dispose it on program release anyway
                    }
                    txFinalized = true;
                }
                throw e;
            } finally {
                // Defensive: if some path slipped through without finalizing
                // (which shouldn't happen given the catch above, but the
                // checkin-failure branch sets txFinalized before returning
                // through here), roll back. Without this an unhandled throw
                // could leak an open tx onto the cached Program.
                if (dispatchOwnsTx && !txFinalized) {
                    try {
                        program.endTransaction(dispatchTxId, false);
                    } catch (Exception ignored) {
                        // last-resort; same justification as the catch above
                    }
                }
                dispatchTxId = -1;
                active = null;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Operator-visible WARN line emitted when {@link #dispatch} evicts a cached
     * Program because of a BufferMgr corruption. Kept here (next to the only call
     * site) so the recovery semantics are grep-able as one block.
     */
    private void logBufferLockRecovery(String procedure, String originalError) {
        try {
            ghidra.util.Msg.warn(this,
                "RPC " + procedure + " hit buffer-lock corruption ("
                + (originalError == null ? "<no message>" : originalError)
                + "); dropping cached program and retrying with recovery.");
        } catch (Exception ignored) {
            // Msg.warn failing (e.g. during shutdown) must not abort the recovery path.
        }
    }

    private static String procedureOf(JsonObject request) {
        try {
            return request.get("procedure").getAsString();
        } catch (Exception e) {
            return "unknown";
        }
    }

    // ---------------------------------------------------------------------------
    // Program resolution (project-level). Called only under {@link #lock}.
    // ---------------------------------------------------------------------------

    /**
     * Open (and cache) the program at {@code path}. Convenience overload with
     * {@code okToRecover=false}; see {@link #openProgram(String, boolean)} for the
     * recovery-on-open semantics.
     */
    private Program openProgram(String path) throws Exception {
        return openProgram(path, false);
    }

    /**
     * Open (and cache) the program at {@code path}. {@code path} is a project path
     * (e.g. {@code "/Mapeditor.exe"}); a bare name with no {@code '/'} is also accepted
     * and resolved by a recursive name search. Returns the cached instance on repeat
     * calls. Throws {@link IllegalArgumentException} if no such program exists.
     *
     * <p>{@code okToRecover} is passed through to {@link DomainFile#getDomainObject}:
     * when true, Ghidra applies any pending recovery change-set left behind by a
     * previous JVM that crashed mid-edit (e.g. an OOM-killed prior RPC server) so the
     * fresh in-memory state matches the on-disk intent. The default (false) is
     * preserved for the normal open path — we are a fresh consumer and don't want to
     * silently pull in another session's unfinished work. Recovery is opted into only
     * by the corruption-recovery retry in {@link #dispatch}.
     */
    private Program openProgram(String path, boolean okToRecover) throws Exception {
        if (project == null) {
            throw new IllegalArgumentException(
                "No project is available; cannot select program '" + path + "'.");
        }
        java.util.List<String> candidates = new java.util.ArrayList<>();
        DomainFile df = resolveFile(path, candidates);
        if (df == null) {
            throw new IllegalArgumentException(noFileMessage(path, candidates));
        }
        String key = normalize(df.getPathname());
        Program cached = open.get(key);
        // Lazy reset: this file is dirty from a previous failed checkin
        // (markDirty was called in checkin's catch block). The cached
        // Program's in-memory state is the post-mutation that didn't land
        // server-side, and the local file is the same. We can't reuse
        // either; force a reset to the server's pre-mutation state by
        // releasing the cached Program, calling df.undoCheckout() to
        // release the checkout AND revert the local file, then proceeding
        // to the normal re-open path which re-checks-out from server.
        //
        // This is the "reset to server state before next successful RPC"
        // guarantee. undoCheckout requires the server connection; if the
        // connection is still down the call throws and this openProgram
        // fails — the caller sees the error, retries when the connection
        // is back, and the reset then succeeds.
        if (dirtyLocalFiles.contains(df)) {
            if (cached != null) {
                try {
                    cached.release(this);
                } catch (Exception ignored) {
                    // best-effort; we drop the cache entry regardless
                }
                open.remove(key);
                cached = null;
            }
            if (df.isVersioned() && df.isCheckedOut()) {
                df.undoCheckout(false, false);
            }
            dirtyLocalFiles.remove(df);
        }
        if (cached != null) {
            return cached;
        }
        if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
            throw new IllegalArgumentException("'" + df.getPathname() + "' is not a Program.");
        }
        // Check out BEFORE opening: a versioned file opened while not checked out yields a
        // read-only in-memory instance whose check-in would fail. On a read-only session we
        // skip checkout — read-only procedures still work; mutating ones fail later at check-in.
        if (df.isVersioned() && !df.isCheckedOut() && !df.isReadOnly()) {
            if (!df.checkout(true, monitor)) { // exclusive
                throw new IllegalArgumentException(
                    "Failed to check out '" + df.getPathname() + "' (held by another user?).");
            }
        }
        // okToUpgrade=true (open older DB versions). okToRecover is parameterized — see
        // the Javadoc above.
        Program p = (Program) df.getDomainObject(this, true, okToRecover, monitor);
        open.put(key, p); // removeEldestEntry fires here; eldest clean entry is released
        return p;
    }

    /**
     * Drop the cached {@link Program} for {@code path} and reopen it with
     * {@code okToRecover=true}. Used by {@link #dispatch}'s corruption-recovery retry
     * when a request hits a {@link #isBufferLockError(Throwable) BufferMgr corruption}
     * (e.g. {@code "Locked buffer: N"} or {@code "Can't checkpoint with locked
     * buffers"}); the on-disk file is fine, but the cached instance's in-memory
     * {@code db.buffers.BufferMgr} is wedged and would re-throw the same error on
     * every subsequent request. Releasing the {@link Program} disposes its
     * {@code BufferMgr} (releasing every pinned {@code BufferNode} regardless of
     * {@code lockCount}); the reopen re-reads buffers from disk.
     *
     * <p>The exclusive checkout lives on the {@link DomainFile} (server-side), not
     * on the {@link Program}, so {@link Program#release release} does NOT orphan the
     * checkout — the subsequent open reuses the same checkout. Release is
     * best-effort: a failed release is itself a symptom of the corruption we're
     * recovering from, so we swallow it and let the reopen take over.
     */
    private Program evictAndReopen(String path) throws Exception {
        java.util.List<String> candidates = new java.util.ArrayList<>();
        DomainFile df = resolveFile(path, candidates);
        if (df == null) {
            throw new IllegalArgumentException(noFileMessage(path, candidates));
        }
        String key = normalize(df.getPathname());
        Program old = open.get(key);
        if (old != null) {
            try {
                old.release(this);
            } catch (Exception ignored) {
                // best-effort; a failed release is part of the corruption we're recovering from
            }
            open.remove(key);
        }
        return openProgram(path, true);
    }

    /**
     * Match the Ghidra 12.1.2 {@code db.buffers.BufferMgr} in-memory-corruption
     * signatures (verified via {@code javap -v} of {@code BufferMgr.class} in
     * {@code Ghidra/Framework/DB/lib/DB.jar}; only {@code BufferMgr} holds the
     * "Locked buffer" strings, so there is no on-disk lock state to clean up —
     * recovery is purely an in-memory eviction). Returns true for:
     * <ul>
     *   <li>{@code "Locked buffer: <id>"} (a {@code BufferNode} was pinned by an
     *       earlier caller that forgot to {@code releaseBuffer(...)})</li>
     *   <li>{@code "Invalid or locked buffer"}</li>
     *   <li>{@code "Can't checkpoint with locked buffers (N locks found)"} and
     *       the matching undo/redo variants — fired by the command's own
     *       checkpoint at the end of {@code applyTo}; the original
     *       {@code "Locked buffer: N"} exception is logged upstream and swallowed
     *       inside the command, so this string is what surfaces to the client.</li>
     *   <li>{@code "Corrupted BufferMgr state"} and {@code "BufferMgr is Corrupt!\n"}</li>
     * </ul>
     * The signature-match style (prefix / exact) mirrors how Ghidra builds each
     * message — the buffer ID, lock count and trailing newline vary.
     */
    static boolean isBufferLockError(String message) {
        if (message == null) {
            return false;
        }
        if (message.startsWith("Locked buffer:")            // "Locked buffer: <id>"
                || message.equals("Invalid or locked buffer")
                || message.startsWith("Can't checkpoint with locked buffers")
                || message.startsWith("Can't undo with locked buffers")
                || message.startsWith("Can't redo with locked buffers")
                || message.equals("Corrupted BufferMgr state")
                || message.startsWith("BufferMgr is Corrupt!")) {
            return true;
        }
        return false;
    }

    /** Walks the cause chain so a wrapped {@code DomainObjectException} -> {@code IOException} matches. */
    static boolean isBufferLockError(Throwable t) {
        for (Throwable cur = t; cur != null; cur = cur.getCause()) {
            if (isBufferLockError(cur.getMessage())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolve a project path to a {@link DomainFile}, or null. Resolution is
     * STRICT: the request's path must match a real project entry exactly.
     * On miss, walks the project tree once to collect up to 5 leaf-name
     * candidates and includes them in the returned null's "did you mean
     * ..." hint via the surrounding caller's error path.
     *
     * <p>Why strict: a previous lenient fallback matched a file by its
     * basename across the whole project (e.g. request
     * {@code "/input/<prog>/<lib>.dll"} silently resolved to
     * {@code "/<lib>.dll"}). The success log line echoed the
     * REQUESTED path, hiding the rewrite, so callers had no way to know
     * the server was operating on a different file. Strict lookup makes
     * the rewrite visible (or impossible): the call either matches
     * exactly or it errors with the candidates.
     *
     * <p>Leaf-name matching is preserved as a hint (candidates shown in
     * the error message) but no longer a fallback. Users who want a
     * shortcut can call {@code ListFiles} to find the canonical path.
     */
    private DomainFile resolveFile(String path) {
        return resolveFile(path, null);
    }

    /**
     * Internal resolver: {@code outCandidates}, if non-null, is filled
     * with up to 5 leaf-name matches when the exact lookup misses. Used
     * to enrich the surrounding caller's error message. Pass null in
     * normal use.
     */
    private DomainFile resolveFile(String path, java.util.List<String> outCandidates) {
        DomainFile df = project.getProjectData().getFile(normalize(path));
        if (df != null) {
            return df;
        }
        // Collect leaf-name candidates across the whole project for the
        // hint; do NOT return one of them as a fallback.
        if (outCandidates != null) {
            String name = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
            collectNameCandidates(project.getProjectData().getRootFolder(), name, outCandidates, 5);
        }
        return null;
    }

    /** Walk the project tree; append up to {@code limit} files whose name matches {@code name}. */
    private static void collectNameCandidates(DomainFolder folder, String name,
            java.util.List<String> out, int limit) {
        for (DomainFile f : folder.getFiles()) {
            if (out.size() >= limit) {
                return;
            }
            if (f.getName().equals(name)) {
                out.add(f.getPathname());
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            if (out.size() >= limit) {
                return;
            }
            collectNameCandidates(sub, name, out, limit);
        }
    }

    private static String normalize(String path) {
        String t = path.trim();
        return t.startsWith("/") ? t : "/" + t;
    }

    /**
     * Build a "no file at PATH" error message. If {@code candidates} has
     * entries, the message includes a "did you mean ..." hint listing
     * them so the caller can correct the path on the next attempt.
     */
    private static String noFileMessage(String path, java.util.List<String> candidates) {
        if (candidates.isEmpty()) {
            return "No file at '" + path + "'.";
        }
        StringBuilder sb = new StringBuilder("No file at '");
        sb.append(path).append("'. Did you mean ");
        for (int i = 0; i < candidates.size(); i++) {
            if (i > 0) {
                sb.append(i == candidates.size() - 1 ? " or " : ", ");
            }
            sb.append('\'').append(candidates.get(i)).append('\'');
        }
        sb.append("?");
        return sb.toString();
    }

    // ---------------------------------------------------------------------------
    // Dirty-file tracking (Phase 2). A "dirty" file's last save+checkin failed,
    // so its on-disk copy may differ from the server. {@link #revertDirtyLocalFiles}
    // brings the local state back in line via {@link DomainFile#undoCheckout}.
    // ---------------------------------------------------------------------------

    /**
     * Record that {@code program}'s file failed its most recent checkin and
     * may now diverge from the Ghidra Server. Idempotent: re-marking an
     * already-dirty file is a no-op. Called only from {@link #checkin} when
     * save or checkin throws. Called only under {@link #lock}.
     */
    private void markDirty(Program program) {
        DomainFile df = program.getDomainFile();
        if (df == null) {
            return;
        }
        dirtyLocalFiles.add(df);
    }

    /**
     * Clear the dirty flag on {@code program}'s file: a successful push now
     * landed and the local copy matches the server. Idempotent. Called from
     * {@link #checkin} on the success path. Called only under {@link #lock}.
     */
    private void clearDirty(Program program) {
        DomainFile df = program.getDomainFile();
        if (df == null) {
            return;
        }
        dirtyLocalFiles.remove(df);
    }

    /**
     * Revert every dirty file's local content to the server's version via
     * {@link DomainFile#undoCheckout(boolean) DomainFile.undoCheckout(false)},
     * which discards the local checkout copy and (for shared projects)
     * re-fetches the file from the Ghidra Server. Best-effort: a single
     * file's failure (e.g. RMI is down right now) is logged and skipped, so
     * a partial pass leaves the dirty set reduced but not empty, ready for
     * a later attempt.
     *
     * <p>Snapshots the dirty set under the lock, then iterates outside the
     * lock: {@code undoCheckout} issues an RMI call to the Ghidra Server and
     * can block on a dead connection; we don't want to hold the dispatch
     * lock for that. The next dispatch observes the cleared entries (via the
     * {@code removed} set below) on subsequent checks.
     *
     * <p>Safe to call when the set is empty — it's a no-op. Wired into both
     * {@link #closeAll} (in-JVM shutdown path) and the server startup hook
     * (cross-JVM path; if a previous JVM exited with dirty files because
     * the connection was down, the next JVM reverts them when the
     * connection is back).
     */
    public void revertDirtyLocalFiles() {
        // Snapshot under the lock so the dispatch loop can't mutate the set
        // mid-iteration. Copy to a local list — iteration itself is lock-free.
        java.util.List<DomainFile> snapshot;
        lock.lock();
        try {
            if (dirtyLocalFiles.isEmpty()) {
                return;
            }
            snapshot = new java.util.ArrayList<>(dirtyLocalFiles);
        } finally {
            lock.unlock();
        }
        java.util.Set<DomainFile> reverted = new HashSet<>();
        for (DomainFile df : snapshot) {
            if (df == null) {
                reverted.add(null); // skip on result-side filter below
                continue;
            }
            try {
                // keep=false: discard the local checkout copy entirely so the
                // local file matches the server's version. force=false: only
                // do it when we can reach the repository server — otherwise
                // we'd risk leaving a stale checkout behind.
                df.undoCheckout(false, false);
                reverted.add(df);
                Msg.info(this, "Reverted dirty local file '" + df.getPathname()
                    + "' to server version (last checkin had failed).");
            } catch (Exception e) {
                Msg.warn(this, "Could not revert dirty local file '" + df.getPathname()
                    + "': " + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + " (will retry on next startup).");
            }
        }
        // Remove successfully-reverted entries under the lock. Failures stay
        // in the set for a later attempt.
        lock.lock();
        try {
            for (DomainFile df : reverted) {
                if (df != null) {
                    dirtyLocalFiles.remove(df);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Phase 3 startup hook: walk the project tree once and revert every
     * versioned file whose local cache reports {@code modifiedSinceCheckout()
     * == true}. This catches dirty files left behind by a previous JVM that
     * exited with the Ghidra Server unreachable (so {@link #closeAll}'s
     * {@link #revertDirtyLocalFiles} couldn't reach the server to undo the
     * checkouts). The on-disk content of those files is stale — undoing the
     * checkout restores the server's version before any in-memory mutation
     * could be observed against it.
     *
     * <p>Called by {@link RpcServer#run} after handler registration and before
     * the accept loop. The walk is bounded by the project's file count (a few
     * hundred ms for a typical repo) and each {@code undoCheckout} is an RMI
     * call, so a slow server connection makes this slower — but it's a
     * one-time cost paid only on JVM start.
     *
     * <p>Best-effort: a single file's failure (e.g. the server is still down
     * right now) is logged and skipped so a transient outage doesn't block
     * the JVM from starting. We don't retry later — {@link
     * #revertDirtyLocalFiles} is the in-JVM retry path for any file whose
     * THIS-JVM checkin fails; cross-JVM retry would require a persistent
     * dirty-file record, which we don't have yet.
     */
    public void revertDirtyLocalFilesOnStartup() {
        if (project == null) {
            return;
        }
        DomainFolder root = project.getProjectData().getRootFolder();
        if (root == null) {
            return;
        }
        Msg.info(this, "Scanning project tree for dirty local files left by a previous JVM...");
        java.util.List<DomainFile> dirty = new java.util.ArrayList<>();
        collectDirtyFiles(root, dirty);
        if (dirty.isEmpty()) {
            Msg.info(this, "No dirty local files found at startup.");
            return;
        }
        Msg.info(this, "Found " + dirty.size() + " dirty local file(s) at startup; reverting...");
        for (DomainFile df : dirty) {
            try {
                df.undoCheckout(false, false);
                Msg.info(this, "Reverted dirty local file '" + df.getPathname()
                    + "' to server version on startup.");
            } catch (Exception e) {
                Msg.warn(this, "Could not revert dirty local file '" + df.getPathname()
                    + "' at startup: " + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + " (skipping; the file's local content may diverge from the server "
                    + "until this JVM can push or revert it).");
            }
        }
    }

    /** Recursive project-tree walk; collect versioned files with local changes not yet pushed. */
    private static void collectDirtyFiles(DomainFolder folder, java.util.List<DomainFile> out) {
        for (DomainFile f : folder.getFiles()) {
            try {
                if (f.isVersioned() && f.modifiedSinceCheckout()) {
                    out.add(f);
                }
            } catch (Exception ignored) {
                // best-effort; a single file's check failing shouldn't abort the whole walk
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectDirtyFiles(sub, out);
        }
    }

    /** Release every program we opened. Call on shutdown; leaves the context empty. */
    public void closeAll() {
        // Revert any dirty local files BEFORE releasing programs: undoCheckout
        // needs the DomainFile reachable, and once we release the cached
        // Program + its checkout, the server-side lock disappears and the
        // revert path becomes ambiguous.
        revertDirtyLocalFiles();
        lock.lock();
        try {
            for (Program p : open.values()) {
                try {
                    p.release(this);
                } catch (Exception ignored) {
                    // best-effort teardown
                }
            }
            open.clear();
        } finally {
            lock.unlock();
        }
    }

    // ---------------------------------------------------------------------------
    // Checkout / check-in (per resolved program). Called only under {@link #lock}.
    // ---------------------------------------------------------------------------

    /**
     * Save + check {@code program}'s file in to the shared server so the change is
     * immediately visible to other clients. Returns null on success (or nothing to
     * push) and an error response if the push fails (per policy the whole call fails).
     *
     * <p>Dirty-tracking: on a push failure (save or checkin threw), {@code df}
     * is added to {@link #dirtyLocalFiles} so the JVM can revert its local
     * divergence from the server at shutdown ({@link #closeAll}) or on the
     * next startup ({@link #revertDirtyLocalFiles}). The early-return error
     * branches (read-only / not checked out) are configuration problems that
     * never touched the on-disk file, so they don't mark the file dirty.
     */
    private RpcResponse checkin(Program program, String procedure) {
        program.flushEvents();
        DomainFile df = program.getDomainFile();
        if (df.isReadOnly()) {
            return RpcResponse.error("Program is read-only; launch the server in commit mode.");
        }
        boolean changed = program.isChanged();
        try {
            if (changed && df.canSave()) {
                df.save(monitor);
            }
            if (!df.isVersioned()) {
                clearDirty(program); // local non-versioned: save is the persistence
                return null;
            }
            if (!df.isCheckedOut()) {
                return RpcResponse.error("File is not checked out; cannot check in.");
            }
            // modifiedSinceCheckout() can read false right after a save in a transient
            // headless checkout, so also honor isChanged() captured pre-save + canCheckin().
            if (changed || df.canCheckin() || df.modifiedSinceCheckout()) {
                // keepCheckedOut=true: the long-running server keeps editing; createKeepFile=false.
                df.checkin(new DefaultCheckinHandler(
                    "RPC " + procedure, true, false), monitor);
            }
            connectionLostFailures = 0; // healthy connection — reset the failure counter
            clearDirty(program); // push landed — any prior dirty flag is now stale
            return null;
        } catch (Exception e) {
            String m = message(e);
            // If the Ghidra Server connection has died mid-session, count it
            // and — once we hit CONNECTION_LOST_THRESHOLD consecutive failures
            // (so a transient TCP blip doesn't immediately restart the JVM) —
            // fire the registered handler so the orchestrator can restart us.
            // We still return the error below; the in-flight request fails for
            // the client, subsequent requests keep failing until either the
            // connection recovers (resets the counter via the success path) or
            // we hit the threshold and exit. Other failure modes (version
            // conflicts, save errors, ...) don't touch the counter — they're
            // not connection-health signals.
            if (isConnectionLost(m)) {
                connectionLostFailures++;
                if (connectionLostFailures >= CONNECTION_LOST_THRESHOLD) {
                    Runnable h = onConnectionLost;
                    if (h != null) {
                        try {
                            h.run();
                        } catch (Exception ignored) {
                            // best-effort; advisory callback
                        }
                    }
                }
            }
            // Deferred cleanup. Don't try to revert in-place: program.undo()
            // is a no-op here because save() above cleared the undo stack
            // (DomainObjectAdapterDB.save -> setChanged(false) -> clearUndo;
            // verified via javap), and df.undoCheckout() requires the server
            // connection — which is exactly what's failing right now. Trying
            // either under outage would just throw and waste effort. Instead,
            // mark the file dirty and let the next successful dispatch reset
            // it lazily in openProgram: evict + undoCheckout (reverts the
            // local file to the server's version) + re-checkout (re-reads
            // from server). If undoCheckout itself fails because the
            // connection is still down, the next request fails too — the
            // caller retries when the connection is back. Phase 2 + Phase 3
            // remain the cross-JVM safety net.
            markDirty(program);
            return RpcResponse.error("Check-in/push failed: " + m);
        }
    }

    private static String message(Throwable t) {
        String m = t.getMessage();
        return (m != null && !m.isEmpty()) ? m : t.getClass().getSimpleName();
    }

    /**
     * Match Ghidra's RMI-connection-lost signature thrown by the repository
     * adapter when an RMI call hits a dead socket. The exact wording is
     * {@code "Not connected to repository server"} (verified against Ghidra
     * 12.1.2; the suffix the user sees in logs — e.g. {@code "(RpcServer)"} —
     * is the consumer name Ghidra appends when wrapping the IOException, so
     * prefix-matching covers all observed variants). If a future Ghidra
     * release changes the wording, add the new signature here; until then,
     * the JVM will keep serving requests through a dead connection (the same
     * spam the user is trying to escape) and just log "Not connected" errors
     * without exiting.
     */
    static boolean isConnectionLost(String message) {
        return message != null && message.startsWith("Not connected to repository server");
    }

    // ---------------------------------------------------------------------------
    // Command execution helpers (operate on the active program)
    // ---------------------------------------------------------------------------

    /** A unit of program mutation that may throw. */
    public interface Write {
        void run() throws Exception;
    }

    /**
     * Run {@code body} inside a transaction on the active program (committed iff it
     * returns normally; otherwise rolled back and rethrown). Always called while
     * holding {@link #lock}.
     *
     * <p>If {@link #dispatch} already opened a transaction for the current
     * request (i.e. a mutating procedure is mid-flight), this just runs the
     * body inside that outer transaction — no nested tx is opened. The outer
     * tx is committed by dispatch BEFORE the checkin attempt
     * (commit-before-checkin; see dispatch's comment block). The rationale
     * is that {@code df.save(...)} requires no open tx on the same DB
     * handle, so holding the dispatch tx open across checkin would fail
     * with "Unable to lock due to active transaction". Callers outside
     * {@link #dispatch} (tests, internal helpers invoked without the
     * request lifecycle) hit the legacy path and get their own self-contained
     * transaction.
     */
    public void runWrite(String description, Write body) throws Exception {
        Program program = active();
        if (dispatchTransactionOpen()) {
            // dispatch owns the tx; just run the body. The success/failure of
            // the body is propagated to the outer request lifecycle, where
            // dispatch decides commit vs. rollback.
            body.run();
            return;
        }
        int txId = program.startTransaction(description);
        boolean committed = false;
        try {
            body.run();
            committed = true;
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    /** Whether {@link #dispatch} currently owns an open transaction. Only meaningful under {@link #lock}. */
    private boolean dispatchTransactionOpen() {
        return dispatchTxId != -1;
    }

    /**
     * Apply a Ghidra {@link Command} to the active program inside a transaction and map
     * the result to a response. Background commands get the real monitor.
     */
    public RpcResponse applyCommand(Command<Program> cmd) throws Exception {
        Program program = active();
        boolean[] ok = {false};
        runWrite(cmd.getName(), () -> {
            if (cmd instanceof BackgroundCommand) {
                @SuppressWarnings("unchecked")
                BackgroundCommand<Program> bg = (BackgroundCommand<Program>) cmd;
                ok[0] = bg.applyTo(program, monitor);
            } else {
                ok[0] = cmd.applyTo(program);
            }
        });
        if (!ok[0]) {
            String s = cmd.getStatusMsg();
            return RpcResponse.error((s != null && !s.isEmpty()) ? s : (cmd.getName() + " failed."));
        }
        return RpcResponse.ok();
    }

    // ---------------------------------------------------------------------------
    // Resolvers (operate on the active program; throw IllegalArgumentException ->
    // turned into error responses)
    // ---------------------------------------------------------------------------

    /** Parse {@code "0x401000"}, {@code "401000"} or {@code "ram:401000"}; null if invalid. */
    public Address parseAddress(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        Address a = tryAddress(t);
        if (a == null && (t.startsWith("0x") || t.startsWith("0X"))) {
            a = tryAddress(t.substring(2));
        }
        return a;
    }

    private Address tryAddress(String s) {
        try {
            return active().getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    public Address requireAddress(String s) {
        Address a = parseAddress(s);
        if (a == null) {
            throw new IllegalArgumentException("Invalid or missing address: " + s);
        }
        return a;
    }

    /**
     * Build an address set from either {@code "addressSet":[{start,end?},...]} or a
     * single {@code "address"}. Throws if neither is present.
     *
     * <p>The {@code end} field (when present) is EXCLUSIVE — the byte at
     * {@code end} is NOT included. The conversion to Ghidra's inclusive
     * {@link AddressSet#addRange} is done by subtracting one. This matches the
     * CLI's {@code --address-set START:END} syntax and standard half-open
     * byte-range convention. A bare {@code {start}} (no end) is a single-byte
     * range {@code [start, start]}.
     */
    public AddressSetView addressSet(JsonObject req) {
        if (req.has("addressSet") && req.get("addressSet").isJsonArray()) {
            AddressSet set = new AddressSet();
            for (JsonElement e : req.getAsJsonArray("addressSet")) {
                JsonObject o = e.getAsJsonObject();
                Address start = requireAddress(o.get("start").getAsString());
                if (o.has("end") && !o.get("end").isJsonNull()) {
                    Address wireEnd = requireAddress(o.get("end").getAsString());
                    if (wireEnd.compareTo(start) <= 0) {
                        throw new IllegalArgumentException(
                            "addressSet entry end '" + wireEnd + "' must be strictly greater "
                            + "than start '" + start + "' (use a bare {start} for a single-byte "
                            + "range, or start:start+1 for an explicit one-byte range).");
                    }
                    set.addRange(start, wireEnd.previous());
                }
                else {
                    set.addRange(start, start);
                }
            }
            return set;
        }
        if (req.has("address")) {
            return new AddressSet(requireAddress(req.get("address").getAsString()));
        }
        throw new IllegalArgumentException("Missing 'address' or 'addressSet'.");
    }

    public Function requireFunctionAt(Address entry) {
        Function f = active().getFunctionManager().getFunctionAt(entry);
        if (f == null) {
            throw new IllegalArgumentException("No function at " + entry + ".");
        }
        return f;
    }

    public Function requireFunctionAt(String address) {
        return requireFunctionAt(requireAddress(address));
    }

    /**
     * Resolve a function by either a hex address (preferred) or an exact
     * function name. Mirrors the {@code "function"} branch of
     * {@code GetXrefsHandler.resolveTarget} so procedures like decompile and
     * disassemble can accept either form from a single {@code --function}
     * flag. Exact-name match (not substring) matches Ghidra's own function
     * dialog behavior; collisions are reported as {@code "multiple functions
     * matched 'foo'"} so the caller knows to switch to an address.
     */
    public Function requireFunction(String spec) {
        if (spec == null || spec.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing function address or name.");
        }
        FunctionManager fm = active().getFunctionManager();
        Address a = parseAddress(spec);
        if (a != null) {
            Function f = fm.getFunctionAt(a);
            if (f != null) {
                return f;
            }
        }
        // Exact-name match; report collisions so silent-prefix-match bugs
        // don't bite callers later (e.g. two functions named foo_main and
        // foo_main_cold).
        Function match = null;
        int matches = 0;
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(spec)) {
                match = f;
                matches++;
                if (matches > 1) {
                    throw new IllegalArgumentException(
                        "Multiple functions matched '" + spec + "'; use an address.");
                }
            }
        }
        if (match != null) {
            return match;
        }
        throw new IllegalArgumentException(diagnoseMissingFunction(spec,
            "No function matched '" + spec + "' (by address or name)."));
    }

    /**
     * Build a rich error explaining why there is no function at {@code spec}.
     * The original "no function matched" wording is preserved verbatim
     * (callers / log scrapers may parse it), then we add:
     * <ul>
     *   <li>what IS at the address — a primary symbol like {@code LAB_00438360}
     *       (label exists but no function body), an Instruction (code is
     *       disassembled but no function wraps it), a Data unit, or just
     *       undefined bytes (raw code, never disassembled),</li>
     *   <li>a copy-pasteable fix: {@code function create --address <addr>},
     *       which runs {@code CreateFunctionCmd} and lets the analyzer
     *       discover the body. For undefined bytes we suggest a disassemble
     *       first so the analyzer has instructions to work with.</li>
     * </ul>
     *
     * <p>This is invoked from {@link #requireFunction} on miss so every
     * caller (currently {@code FlatDecompilerAPI} and {@code Disassemble})
     * produces the same helpful error instead of a bare "no function
     * matched". Disassemble in particular benefits: previously a user
     * asking to disassemble a label-only address would see only the
     * one-line bare error and conclude "nothing to disassemble"; now they
     * see the label name and the {@code function create} fix.
     */
    public String diagnoseMissingFunction(String spec, String originalMsg) {
        Address addr;
        try {
            addr = requireAddress(spec);
        } catch (IllegalArgumentException badAddr) {
            // Not even a parseable address — return the original message;
            // there's nothing more to add.
            return originalMsg;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(originalMsg);
        sb.append(" Nothing decompilable exists at ").append(addr).append(".");
        // 1) Primary symbol (the LAB_xxx label that brought the user here).
        Symbol primary = active().getSymbolTable().getPrimarySymbol(addr);
        String primaryName = primary == null ? null : primary.getName();
        if (primaryName != null) {
            sb.append(" There IS a label there: '").append(primaryName)
              .append("' (primary symbol at ").append(addr).append(").");
        }
        // 2) Listing code unit — disassembled Instruction, Data, or undefined.
        CodeUnit cu = active().getListing().getCodeUnitContaining(addr);
        if (cu == null) {
            sb.append(" No code unit covers the address either — the bytes are unmapped.");
        }
        else if (cu instanceof Instruction) {
            sb.append(" An Instruction is disassembled at that address but no Function wraps it "
                + "(Ghidra's decompiler requires a Function with an entry point to produce C).");
        }
        else if (cu instanceof ghidra.program.model.listing.Data) {
            sb.append(" A Data unit (not code) is defined at that address.");
        }
        else {
            // Undefined bytes — bytes exist but never disassembled. Tell the
            // user how to get instructions here first.
            sb.append(" The bytes at that address are undefined (not yet disassembled).");
        }
        // 3) Fix.
        sb.append(" Fix: create a function at ").append(addr)
          .append(" so the analyzer wraps the body:");
        sb.append("\n  function create --file /<file> --address ").append(addr);
        if (primaryName != null && primaryName.startsWith("LAB_")) {
            sb.append("\nOptionally rename the entry point after creation:");
            sb.append("\n  function rename --file /<file> --address ").append(addr)
              .append(" --name <descriptive_name>");
        }
        if (cu == null) {
            sb.append("\nIf the bytes are unmapped, add a memory block first (memory create), then disassemble, then create the function.");
        }
        else if (!(cu instanceof Instruction)) {
            // Undefined or Data — needs disassembly first so CreateFunctionCmd
            // can compute a body.
            sb.append("\nIf the bytes are not yet instructions, disassemble first:");
            sb.append("\n  function disassemble --file /<file> --address ").append(addr);
        }
        return sb.toString();
    }

    /**
     * Resolve a data type by name/expression (e.g. "int", "char *", "MyStruct[4]").
     *
     * <p>Resolution order:
     * <ol>
     *   <li><b>Multi-segment path</b> ({@code /Cat/Type} or {@code /<archive>/Cat/Type} —
     *       anything with more than one slash): delegate to
     *       {@link DataTypeOps#requireDataTypeByPath}, which is the same lookup
     *       {@code datatype show --path} uses and handles archive-qualified
     *       paths. A miss here is a hard error — the user gave a path and we
     *       either found it or we didn't.</li>
     *   <li><b>C-syntax expression</b> ({@code int}, {@code char *},
     *       {@code MyStruct[4]}, or a bare leaf name like {@code X}): try
     *       Ghidra's {@link DataTypeParser}. This handles built-ins and
     *       unique-by-name user types.</li>
     *   <li><b>Disambiguation</b>: when the parser returns null, distinguish
     *       "leaf name exists in 2+ categories" from "leaf name doesn't exist
     *       at all". For the ambiguous case, list up to 5 candidate paths and
     *       point the caller at the full-path form ({@code --type /Cat/Type}).
     *       For the not-found case, say so plainly.</li>
     * </ol>
     *
     * <p>Single-segment inputs with a leading slash ({@code /X}) are
     * normalised to {@code X} before step 2 — they're treated as a leaf name
     * with a stray slash, not a path. Multi-segment inputs are treated as
     * paths. The two cases are distinguished by counting slashes after
     * position 0: more than one slash means it's a path.
     */
    public DataType dataType(String name) throws Exception {
        if (name == null || name.trim().isEmpty()) {
            return null;
        }
        DataTypeManager dtm = active().getDataTypeManager();
        String parsed = name.trim();
        // Multi-segment path: "/Cat/Type", "/A/B/Type", "/<archive>/Cat/Type".
        // Anything with a second slash past the leading one is unambiguously a
        // path (a leaf name cannot contain '/'). Delegate to the same lookup
        // datatype show --path uses so archive-qualified paths and ambiguous
        // category prefixes are handled the way the user expects. This is the
        // path the user hits when the leaf name is ambiguous in their
        // unprefixed --type; the error from the first call lists candidates
        // and points them here.
        if (parsed.startsWith("/") && parsed.indexOf('/', 1) > 0) {
            return DataTypeOps.requireDataTypeByPath(this, parsed);
        }
        // Strip a leading slash so "/X" and "X" behave identically — the
        // DataTypeParser would fail on the slash otherwise.
        String leaf = parsed.startsWith("/")
            ? parsed.substring(parsed.lastIndexOf('/') + 1)
            : parsed;
        // The C-syntax parser signals "no match" with EITHER a null return
        // OR an InvalidDataTypeException whose message starts with
        // "Unrecognized data type of" (verified across Ghidra 12.1.2 builds;
        // the script.log captures both branches). The exception path fires
        // when the parser rejects the token before the lookup completes —
        // e.g. an ambiguous leaf name, a name with an embedded slash, or
        // a syntax error. Catch it and fall through to the disambiguation
        // check below so the caller sees the same diagnostic regardless of
        // which way the parser signaled the miss.
        DataType dt;
        try {
            dt = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL).parse(leaf);
        } catch (ghidra.program.model.data.InvalidDataTypeException e) {
            dt = null;
        }
        if (dt != null) {
            return dt;
        }
        // Parser returned null (or threw). The previous implementation
        // surfaced a single "Unknown data type: X" message that didn't
        // distinguish "doesn't exist" from "exists in 2+ places, which
        // one?" — chasing the second case as if it were the first is what
        // burned the bug-report time. List candidates so the caller can
        // pick the right one and re-run with a full path.
        throw disambiguationError(dtm, leaf, name);
    }

    /**
     * Build a disambiguation error for an unresolved leaf type name.
     * Walks the program DTM (categories are a program-DTM concept — archives
     * aren't enumerated here; the user can pass the archive-qualified path
     * form to disambiguate archive matches).
     *
     * <ul>
     *   <li>0 matches in program DTM → {@code no data type named "X"}.</li>
     *   <li>2+ matches in program DTM → {@code ambiguous "X": /A/X, /B/X, ...
     *       — pass --type by full path (e.g. --type /A/X)}.</li>
     * </ul>
     * Exactly one match is NOT an error — but in practice if the parser
     * returned null and there is one program-DTM match, the lookup chain
     * (parser + path) has already been exhausted. We fall through to the
     * not-found message rather than returning the lone match, because the
     * parser should have found it. Users who hit that corner case can
     * resolve by passing the full path explicitly.
     */
    private static IllegalArgumentException disambiguationError(DataTypeManager dtm,
            String leaf, String original) {
        java.util.List<String> candidates = new java.util.ArrayList<>();
        java.util.Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType t = it.next();
            if (t == null) continue;
            if (!leaf.equals(t.getName())) continue;
            String p = t.getCategoryPath().getPath();
            if (p == null || p.isEmpty() || "/".equals(p)) {
                p = "/" + t.getName();
            } else {
                p = p + "/" + t.getName();
            }
            candidates.add(p);
        }
        java.util.Collections.sort(candidates);
        if (candidates.size() >= 2) {
            StringBuilder sb = new StringBuilder("ambiguous \"").append(leaf).append("\": ");
            int n = Math.min(5, candidates.size());
            for (int i = 0; i < n; i++) {
                if (i > 0) sb.append(", ");
                sb.append(candidates.get(i));
            }
            if (candidates.size() > 5) sb.append(", ...");
            sb.append(" — pass --type by full path (e.g. --type ")
              .append(candidates.get(0)).append(")");
            return new IllegalArgumentException(sb.toString());
        }
        return new IllegalArgumentException("no data type named \"" + leaf + "\"");
    }

    public DataType requireDataType(String name) throws Exception {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required data type.");
        }
        return dataType(name);
    }

    public Register requireRegister(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Missing required register.");
        }
        Register r = active().getRegister(name.trim());
        if (r == null) {
            throw new IllegalArgumentException("Unknown register: " + name);
        }
        return r;
    }

    /** Find a parameter or local variable of {@code function} by name. */
    public Variable requireVariable(Function function, String name) {
        if (name == null) {
            throw new IllegalArgumentException("Missing required variable name.");
        }
        for (Variable v : function.getAllVariables()) {
            if (name.equals(v.getName())) {
                return v;
            }
        }
        throw new IllegalArgumentException(
            "No variable named '" + name + "' in function " + function.getName() + ".");
    }

    /** SourceType from string (USER_DEFINED default). Accepts case-insensitive names. */
    public SourceType sourceType(String s) {
        return sourceType(s, SourceType.USER_DEFINED);
    }

    public SourceType sourceType(String s, SourceType dflt) {
        if (s == null || s.trim().isEmpty()) {
            return dflt;
        }
        try {
            return SourceType.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown source type: " + s
                + " (use USER_DEFINED, ANALYSIS, IMPORTED, DEFAULT).");
        }
    }

    /** Parse a C-style function signature string into a FunctionSignature. */
    public FunctionSignature parseSignature(String text) throws Exception {
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required signature text.");
        }
        FunctionSignature sig =
            new FunctionSignatureParser(active().getDataTypeManager(), null).parse(null, text);
        if (sig == null) {
            throw new IllegalArgumentException("Could not parse signature: " + text);
        }
        return sig;
    }

    /** A best-effort ServiceProvider for commands that need one (headless = no GUI services). */
    public ServiceProvider serviceProvider() {
        return new ServiceProviderStub();
    }

    /** A decompiler interface opened on the active program. Caller MUST dispose() it. */
    public DecompInterface openedDecompiler() {
        DecompInterface di = new DecompInterface();
        di.openProgram(active());
        return di;
    }

    /** Read an optional int field; {@code dflt} when missing/null. */
    public static int optInt(JsonObject req, String field, int dflt) {
        return (req.has(field) && !req.get(field).isJsonNull())
            ? req.get(field).getAsInt() : dflt;
    }

    /** Read an optional boolean field; {@code dflt} when missing/null. */
    public static boolean optBool(JsonObject req, String field, boolean dflt) {
        return (req.has(field) && !req.get(field).isJsonNull())
            ? req.get(field).getAsBoolean() : dflt;
    }

    /** Read an optional string field; null when missing/null. */
    public static String optStr(JsonObject req, String field) {
        return (req.has(field) && !req.get(field).isJsonNull())
            ? req.get(field).getAsString() : null;
    }

    /**
     * Read a required string field; throws when missing/empty.
     *
     * <p><b>Required vs. optional.</b> The wire contract treats
     * {@code req*} as <em>required</em>: a missing or empty value is
     * an error. The matching CLI flag is responsible for sending the
     * old server-side default explicitly, so the server does not
     * pick defaults for the caller. Use {@code req*} for any field
     * where the server used to read it with {@code optBool/optInt} or
     * with a {@code null} fallback. Use {@code optStr} only for fields
     * whose absence is a real "no value" input (e.g. an auto-named
     * function, an optional comment, a path-or-name lookup).
     */
    public static String reqStr(JsonObject req, String field) {
        String v = optStr(req, field);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("Missing required field '" + field + "'.");
        }
        return v;
    }

    /**
     * Read a required boolean field; throws when missing/null. See
     * {@link #reqStr} for the wire contract: a server-side default is
     * always picked by the caller, not by the server.
     */
    public static boolean reqBool(JsonObject req, String field) {
        if (!req.has(field) || req.get(field).isJsonNull()) {
            throw new IllegalArgumentException("Missing required field '" + field + "'.");
        }
        return req.get(field).getAsBoolean();
    }

    /**
     * Read a required int field; throws when missing/null. See
     * {@link #reqStr} for the wire contract.
     */
    public static int reqInt(JsonObject req, String field) {
        if (!req.has(field) || req.get(field).isJsonNull()) {
            throw new IllegalArgumentException("Missing required field '" + field + "'.");
        }
        return req.get(field).getAsInt();
    }

    // ---------------------------------------------------------------------------
    // Brief request summary for server-side logging.
    // ---------------------------------------------------------------------------

    /**
     * Cap on a single value's text length when summarised for the server log.
     * Anything longer is truncated with a trailing {@code "..."} so each call
     * fits on one log line. 200 chars matches the convention in our notes and
     * is enough to identify a request without dumping full payloads.
     */
    public static final int BRIEF_VALUE_MAX = 200;

    /**
     * Render a request's arguments as a single greppable line for the server
     * log: alphabetically-sorted {@code key=value} pairs, space-separated.
     * The {@code procedure} field is omitted (caller already prefixes it).
     * String values longer than {@link #BRIEF_VALUE_MAX} are truncated with a
     * trailing {@code "..."}; nested objects and arrays are summarised by
     * length (e.g. {@code [tags:2]}). Designed never to throw and never to
     * return null.
     */
    public static String briefArgs(JsonObject req) {
        if (req == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        java.util.TreeMap<String, String> sorted = new java.util.TreeMap<>();
        for (java.util.Map.Entry<String, JsonElement> e : req.entrySet()) {
            String k = e.getKey();
            if ("procedure".equals(k)) {
                continue;
            }
            sorted.put(k, OPAQUE_FIELDS.contains(k)
                ? opaqueSummary(e.getValue())
                : briefValue(e.getValue()));
        }
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : sorted.entrySet()) {
            if (!first) sb.append(' ');
            first = false;
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    /** Render one JSON value as a brief log fragment; never throws, never null. */
    private static String briefValue(JsonElement v) {
        if (v == null || v.isJsonNull()) {
            return "null";
        }
        if (v.isJsonPrimitive()) {
            String s = v.getAsString();
            return truncate(s == null ? v.toString() : s);
        }
        if (v.isJsonArray()) {
            return "[" + v.getAsJsonArray().size() + "]";
        }
        if (v.isJsonObject()) {
            return "{" + v.getAsJsonObject().size() + "}";
        }
        return truncate(v.toString());
    }

    /**
     * Field names whose values are always logged as length only, never as
     * content. {@code bytes} is base64 of a whole binary on ProgramLoader and
     * a raw read on ReadBytes — the contents are unreadable in the log, take
     * hundreds of lines to dump, and risk leaking the input binary into log
     * aggregation. Add more here as we find them.
     */
    private static final java.util.Set<String> OPAQUE_FIELDS =
        java.util.Set.of("bytes");

    /**
     * Length-only summary for a value we treat as opaque (no content in the
     * log). For strings: byte/char count. For arrays/objects: element count.
     * Falls back to {@code "?"} for nulls/primitives we don't expect here.
     */
    private static String opaqueSummary(JsonElement v) {
        if (v == null || v.isJsonNull()) {
            return "?";
        }
        if (v.isJsonPrimitive()) {
            return String.valueOf(v.getAsString().length());
        }
        if (v.isJsonArray()) {
            return "[" + v.getAsJsonArray().size() + "]";
        }
        if (v.isJsonObject()) {
            return "{" + v.getAsJsonObject().size() + "}";
        }
        return "?";
    }

    /** Trim {@code s} to {@link #BRIEF_VALUE_MAX} chars, appending "..." if cut. */
    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        if (s.length() <= BRIEF_VALUE_MAX) {
            return s;
        }
        return s.substring(0, BRIEF_VALUE_MAX) + "...";
    }
}
