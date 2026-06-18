package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.RemoveStackDepthChangeCommand;
import ghidra.program.model.address.Address;

/** Procedure RemoveStackDepthChangeCommand: remove a stack-depth-change value at {@code address}. */
public final class RemoveStackDepthChangeCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new RemoveStackDepthChangeCommand(addr));
    }
}
