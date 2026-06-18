package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;

/**
 * Procedure DecompilerSwitchAnalysisCmd: recover switch tables for the function at
 * {@code address}. Decompiles the function first to feed the command its results.
 */
public final class DecompilerSwitchAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        int timeout = RpcContext.optInt(req, "timeout", 60);
        DecompInterface di = ctx.openedDecompiler();
        try {
            DecompileResults results = di.decompileFunction(f, timeout, ctx.monitor());
            if (results == null || !results.decompileCompleted()) {
                return RpcResponse.error("Decompilation did not complete for " + f.getName() + ".");
            }
            return ctx.applyCommand(new DecompilerSwitchAnalysisCmd(results));
        } finally {
            di.dispose();
        }
    }
}
