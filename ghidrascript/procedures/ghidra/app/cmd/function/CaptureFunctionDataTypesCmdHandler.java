package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CaptureFunctionDataTypesCmd;

/**
 * Procedure CaptureFunctionDataTypesCmd: capture function signatures (as data types)
 * across an address set into the program's own data type manager. The completion
 * listener is a no-op (headless has no UI callback).
 */
public final class CaptureFunctionDataTypesCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new CaptureFunctionDataTypesCmd(
            ctx.program().getDataTypeManager(), ctx.addressSet(req), cmd -> { }));
    }
}
