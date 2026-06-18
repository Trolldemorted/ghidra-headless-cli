package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PreGet: read the PRE comment at an address. */
public final class PreGetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.get(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.PRE, ctx);
    }
    @Override public boolean mutates() { return false; }
}