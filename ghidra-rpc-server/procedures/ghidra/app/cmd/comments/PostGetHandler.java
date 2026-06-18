package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PostGet: read the POST comment at an address. */
public final class PostGetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.get(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.POST, ctx);
    }
    @Override public boolean mutates() { return false; }
}