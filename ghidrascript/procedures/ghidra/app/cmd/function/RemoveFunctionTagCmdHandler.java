package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.RemoveFunctionTagCmd;
import ghidra.program.model.address.Address;

/** Procedure RemoveFunctionTagCmd: remove tag {@code tag} from the function at {@code address}. */
public final class RemoveFunctionTagCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String tag = RpcContext.reqStr(req, "tag");
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new RemoveFunctionTagCmd(tag, entry));
    }
}
