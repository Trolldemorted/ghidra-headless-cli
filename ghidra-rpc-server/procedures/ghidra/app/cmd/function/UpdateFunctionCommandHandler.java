package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

/**
 * Procedure UpdateFunctionCommand: update a function's signature in one shot —
 * calling convention, return type, and the full parameter list.
 *
 * {@code updateType}: DYNAMIC_STORAGE_FORMAL_PARAMS (default), DYNAMIC_STORAGE_ALL_PARAMS,
 * or CUSTOM_STORAGE. {@code parameters}: [{name?, dataType}]. {@code force} overrides
 * conflicting variable storage.
 */
public final class UpdateFunctionCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Program program = ctx.program();
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        String ut = RpcContext.optStr(req, "updateType");
        FunctionUpdateType updateType = (ut == null)
            ? FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS
            : FunctionUpdateType.valueOf(ut.trim().toUpperCase());

        String callingConvention = RpcContext.optStr(req, "callingConvention");

        String returnType = RpcContext.optStr(req, "returnType");
        Variable returnVar = (returnType == null)
            ? null : new ReturnParameterImpl(ctx.requireDataType(returnType), program);

        List<Variable> params = new ArrayList<>();
        if (req.has("parameters") && req.get("parameters").isJsonArray()) {
            for (JsonElement e : req.getAsJsonArray("parameters")) {
                JsonObject p = e.getAsJsonObject();
                params.add(new ParameterImpl(RpcContext.optStr(p, "name"),
                    ctx.requireDataType(RpcContext.reqStr(p, "dataType")), program, source));
            }
        }

        boolean force = RpcContext.optBool(req, "force", false);
        return ctx.applyCommand(new UpdateFunctionCommand(
            f, updateType, callingConvention, returnVar, params, source, force));
    }
}
