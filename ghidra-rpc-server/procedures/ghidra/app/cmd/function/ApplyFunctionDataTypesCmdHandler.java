package procedures.ghidra.app.cmd.function;

import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.program.model.data.DataTypeManager;

/**
 * Procedure ApplyFunctionDataTypesCmd: apply function-definition data types to matching
 * symbols across an address set. Uses the program's own data type manager as the source
 * (headless has no open external archives).
 */
public final class ApplyFunctionDataTypesCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        List<DataTypeManager> managers = List.of(ctx.program().getDataTypeManager());
        return ctx.applyCommand(new ApplyFunctionDataTypesCmd(
            managers, ctx.addressSet(req),
            ctx.sourceType(RpcContext.optStr(req, "source")),
            RpcContext.reqBool(req, "createBookmarks"),
            RpcContext.reqBool(req, "alwaysReplace")));
    }
}
