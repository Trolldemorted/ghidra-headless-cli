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
        String name = RpcContext.reqStr(req, "name");
        // The Ghidra command returns true (a silent no-op) for an unknown tag.
        if (ctx.program().getFunctionManager().getFunctionTagManager().getFunctionTag(name) == null) {
            return RpcResponse.error("No function tag named '" + name + "'.");
        }
        return ctx.applyCommand(new DeleteFunctionTagCmd(name));
    }
}
