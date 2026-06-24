package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetFunctionVarArgsCommand;
import ghidra.program.model.listing.Function;

/** Procedure SetFunctionVarArgsCommand: toggle varargs on the function at {@code address}. */
public final class SetFunctionVarArgsCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        boolean hasVarArgs = RpcContext.reqBool(req, "hasVarArgs");
        return ctx.applyCommand(new SetFunctionVarArgsCommand(f, hasVarArgs));
    }
}
