package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure DecompilerClear: clear the function-level decompiler comment. */
public final class DecompilerClearHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.clear(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.DECOMPILER, ctx);
    }
}