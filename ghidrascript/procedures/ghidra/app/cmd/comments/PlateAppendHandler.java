package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PlateAppend: append text to the PLATE comment at an address. */
public final class PlateAppendHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.append(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.PLATE, procedures.RpcContext.reqStr(req, "text"),
            procedures.RpcContext.optStr(req, "separator"), ctx);
    }
}