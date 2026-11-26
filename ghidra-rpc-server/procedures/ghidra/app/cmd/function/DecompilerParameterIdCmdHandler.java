package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.program.model.symbol.SourceType;

/**
 * Procedure DecompilerParameterIdCmd: use the decompiler to identify parameters/return
 * for functions in the set and commit them.
 */
public final class DecompilerParameterIdCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return ctx.applyCommand(new DecompilerParameterIdCmd(
            "DecompilerParameterId (RPC)",
            ctx.addressSet(req),
            // This argument is Ghidra's sourceTypeClearLevel: signatures at or
            // below it are RESET and re-derived from the decompiler. Default to
            // ANALYSIS (what Ghidra's own analyzer uses); the generic
            // USER_DEFINED default would wipe hand-made signatures.
            ctx.sourceType(RpcContext.optStr(req, "source"), SourceType.ANALYSIS),
            RpcContext.reqBool(req, "commitDataTypes"),
            RpcContext.reqBool(req, "commitVoidReturn"),
            RpcContext.reqInt(req, "timeout")));
    }
}
