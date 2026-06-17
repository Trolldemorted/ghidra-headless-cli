package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.AddMemoryVarCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

/**
 * Procedure AddMemoryVarCmd: add a memory variable (at {@code memoryAddress}) to the
 * function at {@code address}.
 */
public final class AddMemoryVarCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address memAddr = ctx.requireAddress(RpcContext.reqStr(req, "memoryAddress"));
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.optStr(req, "name");
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));
        String dtName = RpcContext.optStr(req, "dataType");
        AddMemoryVarCmd cmd = (dtName == null)
            ? new AddMemoryVarCmd(memAddr, funcEntry, name, source)
            : new AddMemoryVarCmd(memAddr, funcEntry, name, ctx.requireDataType(dtName), source);
        return ctx.applyCommand(cmd);
    }
}
