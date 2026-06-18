package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure DecompilerAppend: append text to the function-level decompiler comment. */
public final class DecompilerAppendHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.append(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.DECOMPILER, procedures.RpcContext.reqStr(req, "text"),
            procedures.RpcContext.optStr(req, "separator"), ctx);
    }
}