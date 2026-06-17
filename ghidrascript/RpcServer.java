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

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final Map<String, RpcProcedure> handlers = new ConcurrentHashMap<>();
    private final AtomicLong clientIds = new AtomicLong();

    private RpcContext context;
    private ExecutorService clientPool;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            Msg.error(this, "No current program; run with -process <program>.");
            return;
        }

        String bind = env("RPC_BIND", "0.0.0.0");
        int port = Integer.parseInt(env("RPC_PORT", "18000"));

        context = new RpcContext(state.getProject(), currentProgram, monitor);
        registerHandlers();

        // analyzeHeadless wraps a post-script's run() in one open transaction named
        // after the script. Our run() blocks in the accept loop the whole session, so
        // that transaction would never close and per-request commits could not land.
        // End it up front so the server owns persistence (checkin/save land live).
        endEnclosingTransaction();

        clientPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "rpc-client");
            t.setDaemon(true);
            return t;
        });

        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(bind, port));
            server.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Msg.info(this, "Listening on " + bind + ":" + port
                    + " program=" + currentProgram.getDomainFile().getPathname());
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

    private void acceptLoop(ServerSocket server) {
        while (!monitor.isCancelled()) {
            final Socket socket;
            try {
                socket = server.accept();
            } catch (SocketTimeoutException timeout) {
                continue; // poll cancellation, then keep waiting
            } catch (IOException e) {
                if (monitor.isCancelled()) {
                    break;
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
                if (monitor.isCancelled()) {
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

        // ghidra.app.decompiler.flatapi (different package -> not found by the
        // procedures.ghidra.app.cmd.function reflection fallback; must be pre-registered).
        register("FlatDecompilerAPI", new procedures.ghidra.app.decompiler.flatapi.FlatDecompilerAPIHandler());
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
