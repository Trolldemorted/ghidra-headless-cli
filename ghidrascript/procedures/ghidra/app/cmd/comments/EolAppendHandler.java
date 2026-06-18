package procedures.ghidra.app.cmd.comments;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcResponse;

/** Procedure EolAppend: append text to the EOL comment at an address. */
public final class EolAppendHandler implements procedures.RpcProcedure {
    @Override public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        return CommentOps.append(ctx.requireAddress(procedures.RpcContext.reqStr(req, "address")),
            CommentOps.Type.EOL, procedures.RpcContext.reqStr(req, "text"),
            procedures.RpcContext.optStr(req, "separator"), ctx);
    }
}