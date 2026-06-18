package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure CreateFunctionCmd: create a function at {@code address}. Optional
 * {@code name} (default FUN_/thunk naming); body is computed by disassembly.
 */
public final class CreateFunctionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.optStr(req, "name"); // null -> default name
        return ctx.applyCommand(new CreateFunctionCmd(
            name, entry, null, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
