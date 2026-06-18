package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DeleteFunctionTagCmd;

/** Procedure DeleteFunctionTagCmd: delete a function tag program-wide. */
public final class DeleteFunctionTagCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new DeleteFunctionTagCmd(RpcContext.reqStr(req, "name")));
    }
}
