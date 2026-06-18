package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.FunctionResultStateStackAnalysisCmd;

/** Procedure FunctionResultStateStackAnalysisCmd: result-state-based stack analysis. */
public final class FunctionResultStateStackAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new FunctionResultStateStackAnalysisCmd(
            ctx.addressSet(req), RpcContext.optBool(req, "forceProcessing", false)));
    }
}
