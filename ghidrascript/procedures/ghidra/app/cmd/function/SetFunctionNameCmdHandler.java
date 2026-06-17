package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.program.model.address.Address;

/** Procedure SetFunctionNameCmd: rename the function whose entry point is {@code address}. */
public final class SetFunctionNameCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.reqStr(req, "name");
        return ctx.applyCommand(
            new SetFunctionNameCmd(entry, name, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
