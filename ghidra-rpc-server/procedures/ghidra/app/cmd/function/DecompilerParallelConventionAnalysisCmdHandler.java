package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DecompilerParallelConventionAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;

/**
 * Procedure DecompilerParallelConventionAnalysisCmd: decompiler-based calling-convention
 * analysis for the function at {@code address}.
 */
public final class DecompilerParallelConventionAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        int timeout = RpcContext.reqInt(req, "timeout");
        DecompInterface di = ctx.openedDecompiler();
        try {
            return ctx.applyCommand(new DecompilerParallelConventionAnalysisCmd(f, di, timeout));
        } finally {
            di.dispose();
        }
    }
}
