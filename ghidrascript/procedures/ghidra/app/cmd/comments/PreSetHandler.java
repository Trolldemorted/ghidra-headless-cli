package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PreSet: set the PRE comment at an address. */
public final class PreSetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.set(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.PRE, procedures.RpcContext.optStr(req, "text"), ctx);
    }
}