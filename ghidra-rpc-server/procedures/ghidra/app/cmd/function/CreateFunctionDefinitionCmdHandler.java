package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import procedures.ghidra.program.model.data.ShowDataTypeHandler;

/**
 * Procedure CreateFunctionDefinitionCmd: create a FunctionDefinition data type
 * from the function at {@code address}.
 *
 * <p>Replaces the previous wrapper around Ghidra's
 * {@link ghidra.app.cmd.function.CreateFunctionDefinitionCmd}. The upstream
 * command loses the calling convention when the source function has a hidden
 * {@code this} parameter (the {@code __thiscall} case) because
 * {@code Function.getSignature(true).getCallingConventionName()} returns
 * {@code "unknown"} and {@code FunctionDefinitionDataType.setCallingConvention}
 * rejects {@code "unknown"} via {@code CompilerSpec.isUnknownCallingConvention}.
 * This handler now builds a {@link CreateFunctionDefinitionFromSourceCmd} that
 * reads {@link ghidra.program.model.listing.Function#getCallingConventionName()}
 * directly.
 *
 * <p>Returns a {@link ShowDataTypeHandler.ConfirmResponse} (path / kind / name)
 * so callers can see the resolved funcdef's project path, including the
 * {@code .conflict} suffix when the name is already present.
 *
 * <p>Needs a {@link ghidra.framework.plugintool.ServiceProvider} (a
 * best-effort stub is supplied in headless, where DataType services may be
 * unavailable). The previous wrapper passed one in; the new custom command
 * does not need it.
 */
public final class CreateFunctionDefinitionCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        CreateFunctionDefinitionFromSourceCmd cmd =
            new CreateFunctionDefinitionFromSourceCmd(entry);
        RpcResponse base = ctx.applyCommand(cmd);
        if (base == null || !base.success) {
            return base;
        }
        DataType dt = cmd.getDataType();
        if (dt == null) {
            return RpcResponse.error(
                "CreateFunctionDefinitionFromSourceCmd succeeded but no data type was recorded.");
        }
        return new ShowDataTypeHandler.ConfirmResponse(
            ctx.program().getDataTypeManager(), dt, "created");
    }
}
