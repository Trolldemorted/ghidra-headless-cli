package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.FunctionStackAnalysisCmd;

/** Procedure FunctionStackAnalysisCmd: analyze stack references for functions in the set. */
public final class FunctionStackAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new FunctionStackAnalysisCmd(
            ctx.addressSet(req), RpcContext.optBool(req, "forceProcessing", false)));
    }
}
