package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateMultipleFunctionsCmd;

/**
 * Procedure CreateMultipleFunctionsCmd: create functions across an address set
 * ({@code address} for a single entry, or {@code addressSet} ranges).
 */
public final class CreateMultipleFunctionsCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new CreateMultipleFunctionsCmd(
            ctx.addressSet(req), ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
