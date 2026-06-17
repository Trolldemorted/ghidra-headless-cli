package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.address.Address;

/** Procedure SetVariableNameCmd: rename a variable {@code oldName}->{@code newName} in a function. */
public final class SetVariableNameCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String oldName = RpcContext.reqStr(req, "oldName");
        String newName = RpcContext.reqStr(req, "newName");
        return ctx.applyCommand(new SetVariableNameCmd(
            funcEntry, oldName, newName, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
