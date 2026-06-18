package procedures.ghidra.app.cmd.comments;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcResponse;

/** Procedure EolSet: set the EOL comment at an address. */
public final class EolSetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.set(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.EOL, procedures.RpcContext.optStr(req, "text"), ctx);
    }
}