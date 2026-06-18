package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetFunctionRepeatableCommentCmd;
import ghidra.program.model.address.Address;

/** Procedure SetFunctionRepeatableCommentCmd: set the function's repeatable comment. */
public final class SetFunctionRepeatableCommentCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String comment = RpcContext.optStr(req, "comment");
        return ctx.applyCommand(new SetFunctionRepeatableCommentCmd(entry, comment == null ? "" : comment));
    }
}
