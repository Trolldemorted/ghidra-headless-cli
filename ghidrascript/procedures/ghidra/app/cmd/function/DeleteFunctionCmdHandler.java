package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.program.model.address.Address;

/** Procedure DeleteFunctionCmd: delete the function at {@code address}. */
public final class DeleteFunctionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new DeleteFunctionCmd(entry));
    }
}
