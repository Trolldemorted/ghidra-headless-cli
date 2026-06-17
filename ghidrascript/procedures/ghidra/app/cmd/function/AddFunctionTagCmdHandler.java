package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.AddFunctionTagCmd;
import ghidra.program.model.address.Address;

/** Procedure AddFunctionTagCmd: add tag {@code tag} to the function at {@code address}. */
public final class AddFunctionTagCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String tag = RpcContext.reqStr(req, "tag");
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new AddFunctionTagCmd(tag, entry));
    }
}
