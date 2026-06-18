package procedures.ghidra.app.cmd.comments;

import procedures.RpcContext;
import procedures.RpcResponse;
import com.google.gson.JsonObject;

/** Procedure PlateGet: read the PLATE comment at an address (typically a function entry). */
public final class PlateGetHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.get(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.PLATE, ctx);
    }
    @Override public boolean mutates() { return false; }
}