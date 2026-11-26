package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/**
 * Procedure DecompilerSet: set the comment the Decompiler window's
 * "Comments &gt; Set..." edits at an address: the Plate Comment at a function's
 * entry point, the Pre Comment anywhere else inside a function.
 */
public final class DecompilerSetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.set(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.DECOMPILER, procedures.RpcContext.optStr(req, "text"), ctx);
    }
}