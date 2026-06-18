package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PostClear: clear the POST comment at an address. */
public final class PostClearHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.clear(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.POST, ctx);
    }
}