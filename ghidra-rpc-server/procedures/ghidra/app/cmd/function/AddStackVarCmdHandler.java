package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.AddStackVarCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;

/** Procedure AddStackVarCmd: add a stack variable to the function at {@code address}. */
public final class AddStackVarCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        int stackOffset = RpcContext.optInt(req, "stackOffset", 0);
        String name = RpcContext.optStr(req, "name");
        DataType dt = ctx.dataType(RpcContext.optStr(req, "dataType")); // null allowed
        return ctx.applyCommand(new AddStackVarCmd(
            funcEntry, stackOffset, name, dt, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
