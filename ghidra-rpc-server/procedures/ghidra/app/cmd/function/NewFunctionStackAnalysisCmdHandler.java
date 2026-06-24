package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.NewFunctionStackAnalysisCmd;

/** Procedure NewFunctionStackAnalysisCmd: newer stack-analysis pass over the set. */
public final class NewFunctionStackAnalysisCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new NewFunctionStackAnalysisCmd(
            ctx.addressSet(req), RpcContext.reqBool(req, "forceProcessing")));
    }
}
