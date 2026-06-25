// RpcServer.java
//
// A TCP ndjson RPC server exposing Ghidra's ghidra.app.cmd.function procedures.
// Run as a headless GhidraScript via analyzeHeadless (see ghidra-headless.sh).
// The script binds a TCP socket and runs an accept loop, so analyzeHeadless stays
// alive serving requests until the process is stopped (or the monitor is cancelled).
//
// Wire protocol (newline-delimited JSON / ndjson):
//   - One JSON object per line; every request has a string "procedure" field.
//   - Program-related procedures also require a "file" field: the target program's
//     project path (e.g. "/Mapeditor.exe"). The server opens/caches it from the project,
//     so one server can serve every program in the repository, not just one.
//   - Exactly one JSON response object per request, on its own line.
//   - Long-lived connection; many clients may connect at once (thread per client).
//
// Dispatch: "procedure" is a Ghidra command's simple name (e.g. "SetFunctionNameCmd").
// Its handler is procedures.ghidra.app.cmd.function.<procedure>Handler. Handlers are
// pre-registered for compile-time linkage; unknown procedures are resolved by
// reflection (drop-in <Name>Handler.java is enough).
//
// SYNCHRONIZATION: per-client I/O is concurrent (one thread each), but RpcContext
// serializes ALL program access behind a single lock (checkout+mutate+checkin run
// atomically). See RpcContext.
//
// Configuration (environment variables):
//   RPC_BIND   interface to bind   (default 0.0.0.0)
//   RPC_PORT   TCP port to listen  (default 18000)
//
//@category RPC
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.TransactionInfo;
import ghidra.util.Msg;
import generic.hash.HashUtilities;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

public class RpcServer extends GhidraScript {

    private static final int ACCEPT_TIMEOUT_MS = 1000;
    private static final String HANDLER_PKG = "procedures.ghidra.app.cmd.function";

    /** How long the shutdown hook waits for the main thread's normal teardown to finish. */
    private static final long SHUTDOWN_WAIT_MS = 20_000;

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final Map<String, RpcProcedure> handlers = new ConcurrentHashMap<>();
    private final AtomicLong clientIds = new AtomicLong();

    private RpcContext context;
    private ExecutorService clientPool;

    /** The accept-loop socket, published so the shutdown hook can interrupt accept(). */
    private volatile ServerSocket serverSocket;
    /** The script's main thread, joined by the shutdown hook so cleanup can complete. */
    private volatile Thread mainThread;
    /** Set by the shutdown hook to stop the accept loop. The headless {@code monitor}'s
     *  cancel() is a no-op, so this flag — not monitor.isCancelled() — drives shutdown. */
    private volatile boolean stopping;

    @Override
    public void run() throws Exception {
        String bind = env("RPC_BIND", "0.0.0.0");
        int port = Integer.parseInt(env("RPC_PORT", "18000"));

        // The server is not bound to a program: it starts with ZERO programs open and
        // resolves each request's target on demand by path. analyzeHeadless still needs a
        // program to process in order to invoke this post-script at all, but that program
        // is only a trigger — we use it solely to close the enclosing transaction (below)
        // and otherwise ignore it, so the initial state is genuinely empty.
        context = new RpcContext(state.getProject(), monitor);
        // Detect mid-session Ghidra Server connection loss in RpcContext.checkin
        // and exit through the same graceful path the SIGTERM shutdown hook uses,
        // so compose / k8s / systemd can restart us with a fresh RMI connection.
        // (Reconnecting a parked JVM to a live Ghidra Server is non-trivial; a
        // clean restart is the simplest correct recovery until we build proper
        // reconnection. RpcContext surfaces the detection as "Not connected to
        // repository server"; without this callback every subsequent request
        // would loop on the same error forever.)
        context.onConnectionLost(() -> {
            Msg.error(this, "Ghidra Server connection lost (RpcContext detected "
                + "'Not connected to repository server' on checkin); exiting so "
                + "the orchestrator can restart the RPC server.");
            stopping = true; // drive the accept loop to exit (monitor.cancel is a no-op)
            ServerSocket s = serverSocket;
            if (s != null) {
                try {
                    s.close(); // interrupt accept() and let the run() finally run
                } catch (IOException ignored) {
                    // already closed
                }
            }
        });
        registerHandlers();

        // Push out the server-side password expiry by re-setting the password to
        // its current value. Fresh user accounts on a -a0 Ghidra Server default to
        // a 24h expiry (see svrREADME "Allows the reset password expiration to be
        // set to a specified number of days"); the account goes stale if not used
        // for that long. Re-setting the same value resets the clock without
        // changing the credential. The launcher passes GHIDRA_PASSWORD into the
        // JVM as -Dghidra.rpc.password via GHIDRA_JAVA_OPTIONS; we read it here
        // and call RepositoryServerAdapter.setPassword(...) on the live server
        // connection. Opt out with GHIDRA_REFRESH_PW=0 (the launcher then doesn't
        // set the property and this block is a no-op). Best-effort: a failure
        // here logs a warning but never blocks the RPC server from starting —
        // the existing password may still be valid, and surfacing the error at
        // startup would mask the real reason auth will fail later.
        refreshPasswordIfRequested();

        // Handle SIGTERM (e.g. `kill` / `docker stop`) gracefully: the JVM halts shutdown
        // hooks without unwinding this blocked thread, so the accept loop's finally and
        // HeadlessAnalyzer's end-of-session teardown (which releases transient checkouts)
        // would otherwise never run. The hook unblocks the loop and waits for that normal
        // path to finish, turning SIGTERM into the same clean exit as cancellation.
        installShutdownHook();

        // analyzeHeadless wraps a post-script's run() in one open transaction on the
        // processed (trigger) program. Our run() blocks in the accept loop the whole
        // session, so that transaction would never close and per-request commits could
        // not land. End it up front so the server owns persistence (checkin/save land live).
        endEnclosingTransaction();

        clientPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "rpc-client");
            t.setDaemon(true);
            return t;
        });

        try (ServerSocket server = new ServerSocket()) {
            serverSocket = server; // publish so the shutdown hook can close it
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(bind, port));
            server.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Msg.info(this, "Listening on " + bind + ":" + port + "; 0 programs open"
                    + " (programs are opened on demand per request)");
            Msg.info(this, "Procedures (" + handlers.size() + "): "
                    + String.join(", ", handlers.keySet()));
            acceptLoop(server);
        } finally {
            clientPool.shutdownNow();
            context.closeAll(); // release programs we opened on demand (not the headless one)
            Msg.info(this, "Stopped.");
        }
    }

    /**
     * End the transaction analyzeHeadless opened around this script so the server runs
     * transaction-free and per-request check-ins land mid-session. endTransaction()
     * needs the int id startTransaction() returned to headless; at startup the wrapper
     * is the most-recently-started tx, so a probe tx gets enclosingId+1.
     */
    private void endEnclosingTransaction() {
        if (currentProgram == null) {
            return; // no trigger program processed -> no enclosing transaction to close
        }
        TransactionInfo tx = currentProgram.getCurrentTransactionInfo();
        if (tx == null) {
            return;
        }
        int probe = currentProgram.startTransaction("rpcserver-probe");
        currentProgram.endTransaction(probe, true);
        int enclosingId = probe - 1;
        try {
            currentProgram.endTransaction(enclosingId, true);
            Msg.info(this, "Ended enclosing headless transaction \"" + tx.getDescription()
                    + "\" (id " + enclosingId + "); check-ins land live.");
        } catch (Exception e) {
            Msg.warn(this, "Could not end enclosing transaction (" + e.getMessage() + ").");
        }
    }

    /**
     * Push out the server-side password expiry by re-setting the password to its
     * current value, if the launcher requested it. Reads {@code -Dghidra.rpc.password}
     * (populated from {@code GHIDRA_PASSWORD} via {@code GHIDRA_JAVA_OPTIONS} in
     * {@code ghidra-headless.sh}), grabs the live {@link RepositoryServerAdapter} for
     * the open project, and calls {@link RepositoryServerAdapter#setPassword}.
     *
     * <p>Best-effort: any failure (auth mode doesn't support self-password change
     * like PKI, transient network error, project not yet connected) logs a warning
     * but does NOT throw. The RPC server has to start either way — if the
     * existing password is still valid the user can keep working, and if it's
     * expired the auth failure will surface clearly on the first RPC call.
     *
     * <p>Cleared-from-memory hygiene: the password is read from the system property
     * into a local char[] and zeroed after the setPassword call returns, so it
     * doesn't linger on the heap. Ghidra's adapter API only takes char[], so we
     * can't use the property's String form directly.
     *
     * <p>Hash format: the server-side {@code UserManager.setPassword} validates
     * the incoming char[] as a SALTED-SHA-256 hash (4-char alphanumeric salt
     * followed by 64 lowercase hex digits, total length
     * {@link HashUtilities#SHA256_SALTED_HASH_LENGTH} = 68). Anything else —
     * including the raw password — throws "Invalid password hash". We must
     * pre-hash with {@link HashUtilities#getSaltedHash} (this is what
     * {@code ClientUtil.changePassword} does internally too). The
     * {@link RepositoryServerAdapter#setPassword} convenience is a thin
     * pass-through to the RMI call and does not hash for us.
     */
    private void refreshPasswordIfRequested() {
        String pw = System.getProperty("ghidra.rpc.password");
        if (pw == null || pw.isEmpty()) {
            return; // launcher didn't pass it (e.g. GHIDRA_REFRESH_PW=0)
        }
        char[] pwChars = pw.toCharArray();
        char[] pwHash = null;
        try {
            RepositoryServerAdapter server = null;
            try {
                server = state.getProject().getRepository().getServer();
            } catch (Exception e) {
                Msg.warn(this, "Password refresh skipped: cannot reach RepositoryServerAdapter ("
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + ").");
                return;
            }
            if (server == null) {
                Msg.info(this, "Password refresh skipped: no repository server "
                    + "(not connected to a remote Ghidra Server?).");
                return;
            }
            if (!server.canSetPassword()) {
                Msg.info(this, "Password refresh skipped: server does not allow self-password "
                    + "change for this auth mode (e.g. PKI/-a2; -a0 local and -a1 Kerberos do).");
                return;
            }
            // Hash to the format the server expects (4-char salt + 64 hex SHA-256).
            // HashUtilities picks a fresh random salt on each call, so the stored
            // hash rotates even though the password value is unchanged — which
            // is exactly what resets the expiry clock on the server.
            pwHash = HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, pwChars);
            boolean ok = server.setPassword(pwHash);
            if (ok) {
                Msg.info(this, "Password refreshed on server (expiry clock reset).");
            } else {
                Msg.warn(this, "Password refresh returned false; server may have rejected the "
                    + "current value as too weak or otherwise invalid.");
            }
        } catch (Exception e) {
            Msg.warn(this, "Password refresh failed: " + e.getClass().getSimpleName()
                + ": " + e.getMessage() + " (RPC server continues; first auth call will "
                + "surface the real reason if the password is actually invalid).");
        } finally {
            java.util.Arrays.fill(pwChars, '\0'); // don't leave the raw pw on the heap
            if (pwHash != null) {
                java.util.Arrays.fill(pwHash, '\0'); // and the hash either
            }
        }
    }

    /**
     * Install a JVM shutdown hook for graceful SIGTERM handling (also `docker stop`, plain
     * `kill`). The hook runs on its own thread when the JVM starts shutting down; it sets
     * {@link #stopping} (the headless {@code monitor.cancel()} is a no-op, so the flag — not
     * the monitor — drives the loop), closes the server socket to interrupt a blocked
     * accept() at once, then joins the main thread. The join is essential: the JVM waits for
     * shutdown hooks to return but NOT for ordinary threads, so without it the process could
     * halt before the main thread runs its cleanup (clientPool shutdown +
     * {@link RpcContext#closeAll()}), which we want to complete in an orderly way.
     *
     * Transient checkouts are released by Ghidra's repository disconnect on shutdown, so a
     * SIGTERM leaves NO stale checkout (verified). Note: Ghidra's own {@code
     * TransientProjectManager} registers a separate raw JVM shutdown hook that force-disposes
     * the still-open remote project, logging "Premature removal of active transient project"
     * (and "use count has gone negative", which also appears on normal headless exits). Those
     * lines are benign Ghidra-internal bookkeeping for force-stopping a parked ghidra://
     * session — the disconnect they perform is what releases the checkouts — and run
     * concurrently with this hook, so they cannot be ordered away from here.
     */
    private void installShutdownHook() {
        mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Msg.info(this, "Shutdown signal received; shutting down gracefully...");
            stopping = true;  // drive the accept loop to exit (monitor.cancel is a no-op here)
            monitor.cancel(); // best-effort cancel of any in-flight work (if supported)
            ServerSocket s = serverSocket;
            if (s != null) {
                try {
                    s.close(); // interrupt a blocked accept() right away
                } catch (IOException ignored) {
                    // already closed / never opened
                }
            }
            try {
                mainThread.join(SHUTDOWN_WAIT_MS); // let the accept-loop teardown finish
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "rpc-shutdown"));
    }

    private void acceptLoop(ServerSocket server) {
        while (!stopping && !monitor.isCancelled()) {
            final Socket socket;
            try {
                socket = server.accept();
            } catch (SocketTimeoutException timeout) {
                continue; // poll the stop flag, then keep waiting
            } catch (IOException e) {
                if (stopping || monitor.isCancelled() || server.isClosed()) {
                    break; // socket closed by the shutdown hook
                }
                Msg.warn(this, "Accept failed: " + e.getMessage());
                continue;
            }
            long id = clientIds.incrementAndGet();
            clientPool.submit(() -> handleClient(socket, id));
        }
    }

    private void handleClient(Socket socket, long clientId) {
        String peer = socket.getRemoteSocketAddress() + " #" + clientId;
        Msg.debug(this, "Client connected: " + peer);
        try (Socket s = socket;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8))) {
            s.setTcpNoDelay(true);
            OutputStream out = s.getOutputStream();
            String line;
            while ((line = in.readLine()) != null) {
                if (stopping || monitor.isCancelled()) {
                    break;
                }
                if (line.trim().isEmpty()) {
                    continue;
                }
                writeLine(out, gson.toJson(process(line)));
            }
        } catch (IOException e) {
            // client went away: nothing actionable
        } finally {
            Msg.debug(this, "Client disconnected: " + peer);
        }
    }

    /** Parse one request line, dispatch to its handler, produce a response. */
    private RpcResponse process(String line) {
        JsonObject request;
        try {
            request = JsonParser.parseString(line).getAsJsonObject();
        } catch (Exception e) {
            return RpcResponse.error("Invalid JSON: " + e.getMessage());
        }
        if (!request.has("procedure") || request.get("procedure").isJsonNull()) {
            return RpcResponse.error("Missing required field 'procedure'.");
        }
        String procedure = request.get("procedure").getAsString();
        RpcProcedure handler = resolve(procedure);
        if (handler == null) {
            return RpcResponse.error("Unknown procedure: " + procedure + ".");
        }
        // Log the call (procedure + brief args) on entry, then the outcome on exit,
        // so every request shows up as a pair of lines in the server log. The args
        // summary is bounded (RpcContext.BRIEF_VALUE_MAX chars per value) so a giant
        // comment or base64 blob can't blow up the log line.
        Msg.info(this, "Rpc #" + Thread.currentThread().getId()
                + " call " + procedure + " " + RpcContext.briefArgs(request));
        RpcResponse response;
        try {
            response = context.dispatch(handler, request); // serializes program access
        } catch (Exception e) {
            String msg = e.getMessage();
            response = RpcResponse.error(msg != null ? msg
                : "Internal error: " + e.getClass().getSimpleName());
        }
        Msg.info(this, "Rpc #" + Thread.currentThread().getId()
                + " done " + procedure + " " + (response.success ? "ok" : "error")
                + (response.success ? "" : ": " + briefError(response)));
        return response;
    }

    /** Trim an error message for the done-line log (don't echo multi-KB messages). */
    private static String briefError(RpcResponse r) {
        if (r == null || r.error == null) {
            return "";
        }
        String s = r.error;
        return s.length() <= 200 ? s : s.substring(0, 200) + "...";
    }

    /** Pre-registered handler, else reflectively load <pkg>.<procedure>Handler. */
    private RpcProcedure resolve(String procedure) {
        RpcProcedure cached = handlers.get(procedure);
        if (cached != null) {
            return cached;
        }
        try {
            Class<?> cls = Class.forName(HANDLER_PKG + "." + procedure + "Handler",
                    true, getClass().getClassLoader());
            if (RpcProcedure.class.isAssignableFrom(cls)) {
                RpcProcedure handler = (RpcProcedure) cls.getDeclaredConstructor().newInstance();
                handlers.put(procedure, handler);
                return handler;
            }
        } catch (Throwable ignored) {
            // no matching handler class
        }
        return null;
    }

    /** Register one handler per non-deprecated ghidra.app.cmd.function command. */
    private void registerHandlers() {
        register("CreateFunctionCmd", new procedures.ghidra.app.cmd.function.CreateFunctionCmdHandler());
        register("CreateMultipleFunctionsCmd", new procedures.ghidra.app.cmd.function.CreateMultipleFunctionsCmdHandler());
        register("CreateThunkFunctionCmd", new procedures.ghidra.app.cmd.function.CreateThunkFunctionCmdHandler());
        register("CreateExternalFunctionCmd", new procedures.ghidra.app.cmd.function.CreateExternalFunctionCmdHandler());
        register("CreateFunctionDefinitionCmd", new procedures.ghidra.app.cmd.function.CreateFunctionDefinitionCmdHandler());
        register("DeleteFunctionCmd", new procedures.ghidra.app.cmd.function.DeleteFunctionCmdHandler());
        register("SetFunctionNameCmd", new procedures.ghidra.app.cmd.function.SetFunctionNameCmdHandler());
        register("SetFunctionRepeatableCommentCmd", new procedures.ghidra.app.cmd.function.SetFunctionRepeatableCommentCmdHandler());
        register("SetReturnDataTypeCmd", new procedures.ghidra.app.cmd.function.SetReturnDataTypeCmdHandler());
        register("SetFunctionVarArgsCommand", new procedures.ghidra.app.cmd.function.SetFunctionVarArgsCommandHandler());
        register("SetFunctionPurgeCommand", new procedures.ghidra.app.cmd.function.SetFunctionPurgeCommandHandler());
        register("SetStackDepthChangeCommand", new procedures.ghidra.app.cmd.function.SetStackDepthChangeCommandHandler());
        register("RemoveStackDepthChangeCommand", new procedures.ghidra.app.cmd.function.RemoveStackDepthChangeCommandHandler());
        register("ApplyFunctionSignatureCmd", new procedures.ghidra.app.cmd.function.ApplyFunctionSignatureCmdHandler());
        register("ApplyFunctionDataTypesCmd", new procedures.ghidra.app.cmd.function.ApplyFunctionDataTypesCmdHandler());
        register("CaptureFunctionDataTypesCmd", new procedures.ghidra.app.cmd.function.CaptureFunctionDataTypesCmdHandler());
        register("UpdateFunctionCommand", new procedures.ghidra.app.cmd.function.UpdateFunctionCommandHandler());
        register("AddFunctionTagCmd", new procedures.ghidra.app.cmd.function.AddFunctionTagCmdHandler());
        register("RemoveFunctionTagCmd", new procedures.ghidra.app.cmd.function.RemoveFunctionTagCmdHandler());
        register("CreateFunctionTagCmd", new procedures.ghidra.app.cmd.function.CreateFunctionTagCmdHandler());
        register("DeleteFunctionTagCmd", new procedures.ghidra.app.cmd.function.DeleteFunctionTagCmdHandler());
        register("ChangeFunctionTagCmd", new procedures.ghidra.app.cmd.function.ChangeFunctionTagCmdHandler());
        register("SetVariableNameCmd", new procedures.ghidra.app.cmd.function.SetVariableNameCmdHandler());
        register("SetVariableDataTypeCmd", new procedures.ghidra.app.cmd.function.SetVariableDataTypeCmdHandler());
        register("SetVariableCommentCmd", new procedures.ghidra.app.cmd.function.SetVariableCommentCmdHandler());
        register("DeleteVariableCmd", new procedures.ghidra.app.cmd.function.DeleteVariableCmdHandler());
        register("AddStackVarCmd", new procedures.ghidra.app.cmd.function.AddStackVarCmdHandler());
        register("AddRegisterVarCmd", new procedures.ghidra.app.cmd.function.AddRegisterVarCmdHandler());
        register("AddMemoryVarCmd", new procedures.ghidra.app.cmd.function.AddMemoryVarCmdHandler());
        register("FunctionStackAnalysisCmd", new procedures.ghidra.app.cmd.function.FunctionStackAnalysisCmdHandler());
        register("NewFunctionStackAnalysisCmd", new procedures.ghidra.app.cmd.function.NewFunctionStackAnalysisCmdHandler());
        register("FunctionPurgeAnalysisCmd", new procedures.ghidra.app.cmd.function.FunctionPurgeAnalysisCmdHandler());
        register("FunctionResultStateStackAnalysisCmd", new procedures.ghidra.app.cmd.function.FunctionResultStateStackAnalysisCmdHandler());
        register("DecompilerParameterIdCmd", new procedures.ghidra.app.cmd.function.DecompilerParameterIdCmdHandler());
        register("DecompilerSwitchAnalysisCmd", new procedures.ghidra.app.cmd.function.DecompilerSwitchAnalysisCmdHandler());
        register("DecompilerParallelConventionAnalysisCmd", new procedures.ghidra.app.cmd.function.DecompilerParallelConventionAnalysisCmdHandler());

        // Procedures outside procedures.ghidra.app.cmd.function are not found by the
        // reflection fallback, so they must be pre-registered here.
        register("FlatDecompilerAPI", new procedures.ghidra.app.decompiler.flatapi.FlatDecompilerAPIHandler());
        register("ProgramLoader", new procedures.ghidra.app.util.importer.ProgramLoaderHandler());
        register("Analyze", new procedures.ghidra.app.plugin.core.analysis.AnalyzeHandler());
        register("Disassemble", new procedures.ghidra.program.model.listing.DisassembleHandler());
        register("Listings", new procedures.ghidra.program.model.listing.ListingsHandler());
        // Unified function search (replaces FindFunctionsByName + FindFunctionsByTag,
        // adds address lookup). See FindFunctionHandler.java for dispatch rules.
        register("FindFunction", new procedures.ghidra.program.model.listing.FindFunctionHandler());
        register("GetXrefs", new procedures.ghidra.program.model.listing.GetXrefsHandler());
        register("GetImports", new procedures.ghidra.program.model.listing.GetImportsHandler());
        register("GetExports", new procedures.ghidra.program.model.listing.GetExportsHandler());
        register("Callgraph", new procedures.ghidra.program.model.listing.CallgraphHandler());
        // Memory: static-memory labels (create/rename/delete/set-primary/list/lookup/get) + raw bytes.
        register("CreateLabel", new procedures.ghidra.program.model.listing.CreateLabelHandler());
        register("RenameLabel", new procedures.ghidra.program.model.listing.RenameLabelHandler());
        register("DeleteLabel", new procedures.ghidra.program.model.listing.DeleteLabelHandler());
        register("SetPrimary", new procedures.ghidra.program.model.listing.SetPrimaryLabelHandler());
        register("ListLabels", new procedures.ghidra.program.model.listing.ListLabelsHandler());
        register("LookupLabel", new procedures.ghidra.program.model.listing.LookupLabelHandler());
        register("GetLabel", new procedures.ghidra.program.model.listing.GetLabelHandler());
        register("ReadBytes", new procedures.ghidra.program.model.listing.ReadBytesHandler());
        // Memory undefine: remove listing entries (Data/Instruction definitions)
        // at one or more addresses; bytes are preserved. Mirrors the GUI's
        // "Clear Code Bytes" action; useful for undoing an apply-type, fixing
        // accidental overlaps, or stripping disassembled instructions.
        register("ClearCodeUnits", new procedures.ghidra.program.model.listing.ClearCodeUnitsHandler());
        // Strings: substring/regex search over the program's defined-string set
        // (--query optional; empty = list all), point lookup at one address,
        // mutating DefineString for materializing a string at an address, and
        // DeleteString for clearing the Data type (bytes preserved).
        register("SearchStrings", new procedures.ghidra.program.model.listing.SearchStringsHandler());
        register("GetString", new procedures.ghidra.program.model.listing.GetStringHandler());
        register("DefineString", new procedures.ghidra.program.model.listing.DefineStringHandler());
        register("DeleteString", new procedures.ghidra.program.model.listing.DeleteStringHandler());
        register("ListFiles", new procedures.ghidra.framework.model.ListFilesHandler());
        register("FileMetadata", new procedures.ghidra.framework.model.FileMetadataHandler());
        register("DeleteFile", new procedures.ghidra.framework.model.DeleteFileHandler());

        // Data-type management: list / show / create / replace / edit / delete / apply.
        // Built-ins (path "/" + BuiltIns/ANSI_C/windows_vs archive) are rejected by
        // edit/delete. Create fails on a name collision; Replace uses
        // DataTypeConflictHandler.REPLACE_HANDLER (silently overwrites in place).
        register("ListDataTypes", new procedures.ghidra.program.model.data.ListDataTypesHandler());
        register("ShowDataType", new procedures.ghidra.program.model.data.ShowDataTypeHandler());
        register("CreateDataType", new procedures.ghidra.program.model.data.CreateDataTypeHandler());
        register("ReplaceDataType", new procedures.ghidra.program.model.data.ReplaceDataTypeHandler());
        register("EditDataType", new procedures.ghidra.program.model.data.EditDataTypeHandler());
        register("DeleteDataType", new procedures.ghidra.program.model.data.DeleteDataTypeHandler());
        register("ApplyDataType", new procedures.ghidra.program.model.data.ApplyDataTypeHandler());
        // Per-element field setters: set a struct/union field's comment, its
        // type, or its name. All three go through DataTypeOps.resolveFieldIndex
        // for the shared <name|@offset|N> field-spec convention. The type-level
        // description is set via the `description` field on EditDataType
        // (above) — typedefs reject setDescription with
        // UnsupportedOperationException, which the handler turns into a clear
        // "edit the underlying type instead" error.
        register("SetDataTypeFieldComment", new procedures.ghidra.program.model.data.SetDataTypeFieldCommentHandler());
        register("SetDataTypeVariantComment", new procedures.ghidra.program.model.data.SetDataTypeVariantCommentHandler());
        register("SetDataTypeFieldType", new procedures.ghidra.program.model.data.SetDataTypeFieldTypeHandler());
        register("SetDataTypeFieldName", new procedures.ghidra.program.model.data.SetDataTypeFieldNameHandler());

        // Comment operations: 6 types x 4 ops = 24 procedures. Five CodeUnit-level
        // types (EOL/PRE/POST/REPEATABLE/PLATE) operate on the CodeUnit at the given
        // address; DECOMPILER is function-level (Function.setComment) and resolves
        // the address to the containing function. Set/Append use SetCommentCmd /
        // AppendCommentCmd for proper undo/redo on the CodeUnit path.
        register("EolGet", new procedures.ghidra.app.cmd.comments.EolGetHandler());
        register("EolSet", new procedures.ghidra.app.cmd.comments.EolSetHandler());
        register("EolAppend", new procedures.ghidra.app.cmd.comments.EolAppendHandler());
        register("EolClear", new procedures.ghidra.app.cmd.comments.EolClearHandler());
        register("PreGet", new procedures.ghidra.app.cmd.comments.PreGetHandler());
        register("PreSet", new procedures.ghidra.app.cmd.comments.PreSetHandler());
        register("PreAppend", new procedures.ghidra.app.cmd.comments.PreAppendHandler());
        register("PreClear", new procedures.ghidra.app.cmd.comments.PreClearHandler());
        register("PostGet", new procedures.ghidra.app.cmd.comments.PostGetHandler());
        register("PostSet", new procedures.ghidra.app.cmd.comments.PostSetHandler());
        register("PostAppend", new procedures.ghidra.app.cmd.comments.PostAppendHandler());
        register("PostClear", new procedures.ghidra.app.cmd.comments.PostClearHandler());
        register("PlateGet", new procedures.ghidra.app.cmd.comments.PlateGetHandler());
        register("PlateSet", new procedures.ghidra.app.cmd.comments.PlateSetHandler());
        register("PlateAppend", new procedures.ghidra.app.cmd.comments.PlateAppendHandler());
        register("PlateClear", new procedures.ghidra.app.cmd.comments.PlateClearHandler());
        register("RepeatableGet", new procedures.ghidra.app.cmd.comments.RepeatableGetHandler());
        register("RepeatableSet", new procedures.ghidra.app.cmd.comments.RepeatableSetHandler());
        register("RepeatableAppend", new procedures.ghidra.app.cmd.comments.RepeatableAppendHandler());
        register("RepeatableClear", new procedures.ghidra.app.cmd.comments.RepeatableClearHandler());
        register("DecompilerGet", new procedures.ghidra.app.cmd.comments.DecompilerGetHandler());
        register("DecompilerSet", new procedures.ghidra.app.cmd.comments.DecompilerSetHandler());
        register("DecompilerAppend", new procedures.ghidra.app.cmd.comments.DecompilerAppendHandler());
        register("DecompilerClear", new procedures.ghidra.app.cmd.comments.DecompilerClearHandler());
    }

    private void register(String procedure, RpcProcedure handler) {
        handlers.put(procedure, handler);
    }

    private static void writeLine(OutputStream out, String json) throws IOException {
        synchronized (out) {
            out.write(json.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();
        }
    }

    private static String env(String key, String dflt) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? dflt : v;
    }
}
