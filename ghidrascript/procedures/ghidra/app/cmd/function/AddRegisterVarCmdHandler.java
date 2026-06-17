package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.AddRegisterVarCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;

/** Procedure AddRegisterVarCmd: add a register variable to the function at {@code address}. */
public final class AddRegisterVarCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Register reg = ctx.requireRegister(RpcContext.reqStr(req, "register"));
        String name = RpcContext.optStr(req, "name");
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));
        String dtName = RpcContext.optStr(req, "dataType");
        AddRegisterVarCmd cmd = (dtName == null)
            ? new AddRegisterVarCmd(funcEntry, reg, name, source)
            : new AddRegisterVarCmd(funcEntry, reg, name, ctx.requireDataType(dtName), source);
        return ctx.applyCommand(cmd);
    }
}
