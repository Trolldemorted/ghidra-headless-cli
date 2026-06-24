package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure CreateThunkFunctionCmd: create a thunk function at {@code address}. If
 * {@code referencedFunctionAddress} is given the thunk points there; otherwise the
 * thunked function is auto-detected.
 */
public final class CreateThunkFunctionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String refStr = RpcContext.optStr(req, "referencedFunctionAddress");
        CreateThunkFunctionCmd cmd;
        if (refStr != null) {
            cmd = new CreateThunkFunctionCmd(entry, null, ctx.requireAddress(refStr));
        } else {
            cmd = new CreateThunkFunctionCmd(entry, RpcContext.reqBool(req, "checkExisting"));
        }
        return ctx.applyCommand(cmd);
    }
}
