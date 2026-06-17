package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.address.Address;

/**
 * Procedure ApplyFunctionSignatureCmd: apply a C-style {@code signature} to the
 * function at {@code address} (e.g. "int foo(char *, int)").
 */
public final class ApplyFunctionSignatureCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new ApplyFunctionSignatureCmd(entry,
            ctx.parseSignature(RpcContext.reqStr(req, "signature")),
            ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
