package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetStackDepthChangeCommand;
import ghidra.program.model.address.Address;

/** Procedure SetStackDepthChangeCommand: set the stack-depth-change value at {@code address}. */
public final class SetStackDepthChangeCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        int depthChange = RpcContext.reqInt(req, "stackDepthChange");
        return ctx.applyCommand(new SetStackDepthChangeCommand(addr, depthChange));
    }
}
