// RpcServer.java
//
// A TCP ndjson RPC server exposing Ghidra's ghidra.app.cmd.function procedures.
// Run as a headless GhidraScript via analyzeHeadless (see ghidra-headless.sh).
// The script binds a TCP socket and runs an accept loop, so analyzeHeadless stays
// alive serving requests until the process is stopped (or the monitor is cancelled).
//
// Wire protocol (newline-delimited JSON / ndjson):
//   - One JSON object per line; every request has a string "procedure" field.
//   - Program-related procedures also require a "program" field: the target program's
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
import ghidra.framework.model.TransactionInfo;
import ghidra.util.Msg;

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
        registerHandlers();

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
        Msg.info(this, "Client connected: " + peer);
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
            Msg.info(this, "Client disconnected: " + peer);
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
        try {
            return context.dispatch(handler, request); // serializes program access
        } catch (Exception e) {
            String msg = e.getMessage();
            return RpcResponse.error(msg != null ? msg
                : "Internal error: " + e.getClass().getSimpleName());
        }
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
