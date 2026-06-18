package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateFunctionDefinitionCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure CreateFunctionDefinitionCmd: create a FunctionDefinition data type from
 * the function at {@code address}. Needs a ServiceProvider (a best-effort stub is
 * supplied in headless, where DataType services may be unavailable).
 */
public final class CreateFunctionDefinitionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new CreateFunctionDefinitionCmd(entry, ctx.serviceProvider()));
    }
}
