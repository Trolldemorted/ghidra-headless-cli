package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateExternalFunctionCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure CreateExternalFunctionCmd: create an external function {@code name} in
 * library {@code library}, optionally bound to memory {@code address}.
 */
public final class CreateExternalFunctionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String library = RpcContext.reqStr(req, "library");
        String name = RpcContext.reqStr(req, "name");
        String addrStr = RpcContext.optStr(req, "address");
        Address addr = (addrStr == null) ? null : ctx.requireAddress(addrStr);
        return ctx.applyCommand(new CreateExternalFunctionCmd(
            library, name, addr, ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
