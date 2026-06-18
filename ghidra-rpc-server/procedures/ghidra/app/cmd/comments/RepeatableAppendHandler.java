package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure RepeatableAppend: append text to the REPEATABLE comment at an address. */
public final class RepeatableAppendHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.append(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.REPEATABLE, procedures.RpcContext.reqStr(req, "text"),
            procedures.RpcContext.optStr(req, "separator"), ctx);
    }
}