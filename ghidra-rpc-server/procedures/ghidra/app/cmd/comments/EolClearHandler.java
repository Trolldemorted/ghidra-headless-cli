package procedures.ghidra.app.cmd.comments;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcResponse;

/** Procedure EolClear: clear the EOL comment at an address. */
public final class EolClearHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.clear(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.EOL, ctx);
    }
}