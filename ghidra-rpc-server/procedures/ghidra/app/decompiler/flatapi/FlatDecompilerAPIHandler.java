package procedures.ghidra.app.decompiler.flatapi;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;

/**
 * Procedure FlatDecompilerAPI: decompile the function at {@code address} to C source
 * via Ghidra's {@link FlatDecompilerAPI} and return the text.
 *
 * Read-only: decompilation never modifies the program, so {@link #mutates()} is false
 * and the file is not checked in (it is still checked out by dispatch, per policy).
 *
 * <p>Missing-function errors are enriched by
 * {@link RpcContext#requireFunction} (which calls
 * {@link RpcContext#diagnoseMissingFunction}) — they include what IS at the
 * address (label, instruction, data, undefined bytes), and a copy-pasteable
 * {@code function create} command. The same enrichment applies to
 * {@code Disassemble} so the two procedures produce the same helpful
 * error on miss.
 */
public final class FlatDecompilerAPIHandler implements RpcProcedure {

    /** Used when the client sends {@code timeoutSecs <= 0} (previously: unlimited). */
    static final int DEFAULT_TIMEOUT_SECS = 300;
    /** Upper bound on a client-supplied timeout. */
    static final int MAX_TIMEOUT_SECS = 3600;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        // `address` accepts either a hex address or an exact function name
        // (resolved via RpcContext.requireFunction). Names take one extra
        // lookup pass but let callers pipe `--function main` without having
        // to resolve the address first. requireFunction throws with a
        // diagnosed error message on miss — see RpcContext.diagnoseMissingFunction.
        Function function = ctx.requireFunction(RpcContext.reqStr(req, "address"));
        int timeoutSecs = RpcContext.reqInt(req, "timeoutSecs");

        // FlatDecompilerAPI lazily opens a DecompInterface; dispose() releases it.
        FlatProgramAPI flat = new FlatProgramAPI(ctx.program(), ctx.monitor());
        FlatDecompilerAPI api = new FlatDecompilerAPI(flat);
        try {
            // Always bounded: decompile(function) means "no timeout", and this
            // read-only call (no write password) holds the server-wide lock.
            int bounded = (timeoutSecs > 0) ? Math.min(timeoutSecs, MAX_TIMEOUT_SECS)
                : DEFAULT_TIMEOUT_SECS;
            String c = api.decompile(function, bounded);
            return new DecompileResponse(function.getName(),
                function.getEntryPoint().toString(), c);
        } finally {
            api.dispose();
        }
    }

    /** Decompilation does not change the program, so no check-in is required. */
    @Override
    public boolean mutates() {
        return false;
    }

    /** Success response carrying the decompiled C source (serialized by gson). */
    static final class DecompileResponse extends RpcResponse {
        final String function;
        final String address;
        final String decompilation;

        DecompileResponse(String function, String address, String decompilation) {
            this.success = true;
            this.function = function;
            this.address = address;
            this.decompilation = decompilation;
        }
    }
}
