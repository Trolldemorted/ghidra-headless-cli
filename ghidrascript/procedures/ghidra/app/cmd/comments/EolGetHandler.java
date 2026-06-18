package procedures.ghidra.app.cmd.comments;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcResponse;

/** Procedure EolGet: read the EOL comment at an address. */
public final class EolGetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.get(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.EOL, ctx);
    }
    @Override public boolean mutates() { return false; }
}