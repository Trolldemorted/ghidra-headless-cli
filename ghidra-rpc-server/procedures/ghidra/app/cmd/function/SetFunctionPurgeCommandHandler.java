package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetFunctionPurgeCommand;
import ghidra.program.model.listing.Function;

/** Procedure SetFunctionPurgeCommand: set the stack purge size of the function at {@code address}. */
public final class SetFunctionPurgeCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        int purge = RpcContext.optInt(req, "purge", 0);
        return ctx.applyCommand(new SetFunctionPurgeCommand(f, purge));
    }
}
