package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure RepeatableSet: set the REPEATABLE comment at an address. */
public final class RepeatableSetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.set(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.REPEATABLE, procedures.RpcContext.optStr(req, "text"), ctx);
    }
}