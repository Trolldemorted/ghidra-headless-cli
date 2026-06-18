package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure RepeatableClear: clear the REPEATABLE comment at an address. */
public final class RepeatableClearHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.clear(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.REPEATABLE, ctx);
    }
}