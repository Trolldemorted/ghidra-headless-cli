package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateFunctionTagCmd;

/** Procedure CreateFunctionTagCmd: create a new function tag (with optional comment). */
public final class CreateFunctionTagCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String name = RpcContext.reqStr(req, "name");
        String comment = RpcContext.optStr(req, "comment");
        CreateFunctionTagCmd cmd = (comment == null)
            ? new CreateFunctionTagCmd(name)
            : new CreateFunctionTagCmd(name, comment);
        return ctx.applyCommand(cmd);
    }
}
