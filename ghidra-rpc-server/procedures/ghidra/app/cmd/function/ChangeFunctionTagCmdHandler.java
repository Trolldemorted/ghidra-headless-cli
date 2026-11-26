package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.ChangeFunctionTagCmd;

/**
 * Procedure ChangeFunctionTagCmd: edit a tag's name or comment program-wide.
 * {@code field} selects what changes: "name" (default) or "comment".
 */
public final class ChangeFunctionTagCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String tagName = RpcContext.reqStr(req, "tagName");
        String value = RpcContext.reqStr(req, "value");
        String field = RpcContext.optStr(req, "field");
        // Only the two documented values: a typo such as "coment" used to fall
        // through to a rename, replacing the tag's NAME with the comment text.
        boolean isComment = "comment".equalsIgnoreCase(field);
        if (!isComment && field != null && !field.isEmpty() && !"name".equalsIgnoreCase(field)) {
            return RpcResponse.error("Invalid 'field' '" + field + "': must be name or comment.");
        }
        int type = isComment
            ? ChangeFunctionTagCmd.TAG_COMMENT_CHANGED
            : ChangeFunctionTagCmd.TAG_NAME_CHANGED;
        return ctx.applyCommand(new ChangeFunctionTagCmd(tagName, value, type));
    }
}
