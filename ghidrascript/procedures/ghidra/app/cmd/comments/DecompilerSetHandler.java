package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure DecompilerSet: set the function-level decompiler comment at an address. */
public final class DecompilerSetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.set(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.DECOMPILER, procedures.RpcContext.optStr(req, "text"), ctx);
    }
}