package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PlateClear: clear the PLATE comment at an address. */
public final class PlateClearHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.clear(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.PLATE, ctx);
    }
}