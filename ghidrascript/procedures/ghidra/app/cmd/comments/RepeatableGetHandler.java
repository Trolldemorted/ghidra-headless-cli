package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure RepeatableGet: read the REPEATABLE comment at an address. */
public final class RepeatableGetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.get(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.REPEATABLE, ctx);
    }
    @Override public boolean mutates() { return false; }
}