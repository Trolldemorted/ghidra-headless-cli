package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;

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
            ctx.sourceType(RpcContext.optStr(req, "source")),
            RpcContext.optBool(req, "commitDataTypes", true),
            RpcContext.optBool(req, "commitVoidReturn", true),
            RpcContext.optInt(req, "timeout", 60)));
    }
}
