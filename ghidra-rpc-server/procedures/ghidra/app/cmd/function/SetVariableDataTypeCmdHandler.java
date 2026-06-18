package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.program.model.address.Address;

/** Procedure SetVariableDataTypeCmd: set a variable's data type in a function. */
public final class SetVariableDataTypeCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String varName = RpcContext.reqStr(req, "name");
        return ctx.applyCommand(new SetVariableDataTypeCmd(funcEntry, varName,
            ctx.requireDataType(RpcContext.reqStr(req, "dataType")),
            ctx.sourceType(RpcContext.optStr(req, "source"))));
    }
}
