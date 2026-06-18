package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.FunctionPurgeAnalysisCmd;

/** Procedure FunctionPurgeAnalysisCmd: compute stack purge for functions in the set. */
public final class FunctionPurgeAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new FunctionPurgeAnalysisCmd(ctx.addressSet(req)));
    }
}
