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
 */
public final class FlatDecompilerAPIHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        // `address` accepts either a hex address or an exact function name
        // (resolved via RpcContext.requireFunction). Names take one extra
        // lookup pass but let callers pipe `--function main` without having
        // to resolve the address first.
        Function function = ctx.requireFunction(RpcContext.reqStr(req, "address"));
        int timeoutSecs = RpcContext.optInt(req, "timeoutSecs", 0);

        // FlatDecompilerAPI lazily opens a DecompInterface; dispose() releases it.
        FlatProgramAPI flat = new FlatProgramAPI(ctx.program(), ctx.monitor());
        FlatDecompilerAPI api = new FlatDecompilerAPI(flat);
        try {
            String c = (timeoutSecs > 0)
                ? api.decompile(function, timeoutSecs)
                : api.decompile(function);
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
