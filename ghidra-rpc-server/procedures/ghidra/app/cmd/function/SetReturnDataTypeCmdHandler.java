package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetReturnDataTypeCmd;
import ghidra.program.model.address.Address;

/** Procedure SetReturnDataTypeCmd: set the return data type of the function at {@code address}. */
public final class SetReturnDataTypeCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        return ctx.applyCommand(new SetReturnDataTypeCmd(entry,
            ctx.requireDataType(RpcContext.reqStr(req, "dataType")),
            ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
