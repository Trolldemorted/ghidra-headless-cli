package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
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
 *
 * <p><b>Success means verified (2026-08-06 #391).</b> Ghidra's
 * {@code Function.updateFunction} does not always reflect every requested
 * edit on the next read: in one batch, callers observed
 * {@code UpdateFunctionCommand} returning {@code true} while a subsequent
 * {@code function decompile} showed the return type and parameter names
 * unchanged. Re-issuing the byte-identical command made the changes stick.
 * Ghidra does not throw in that case — {@code applyTo} returns
 * {@code true} with status {@code ""}. To make {@code success} mean
 * "the requested edits are observable on the next read", this handler
 * runs a verification pass after the command returns: it compares the
 * requested return-type and per-parameter names against what
 * {@code function.getReturnType()} / {@code function.getParameter(i)}
 * actually return, and surfaces a non-success response with a precise
 * diff if any disagree. The transaction has already committed at that
 * point (Ghidra has no rollback API for {@code updateFunction}), so
 * verification failure cannot undo the writes — but it CAN make the
 * caller retry, which is the observed workaround.
 */
public final class UpdateFunctionCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Program program = ctx.program();
        Function f = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        String ut = RpcContext.reqStr(req, "updateType");
        FunctionUpdateType updateType;
        try {
            updateType = FunctionUpdateType.valueOf(ut.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid 'updateType' '" + ut
                + "': must be DYNAMIC_STORAGE_FORMAL_PARAMS, DYNAMIC_STORAGE_ALL_PARAMS, or CUSTOM_STORAGE.");
        }

        String callingConvention = RpcContext.optStr(req, "callingConvention");

        String returnType = RpcContext.reqStr(req, "returnType");
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

        boolean force = RpcContext.reqBool(req, "force");
        RpcResponse base = ctx.applyCommand(new UpdateFunctionCommand(
            f, updateType, callingConvention, returnVar, params, source, force));
        if (base == null || !base.success) {
            return base;
        }

        // Verification pass — see Javadoc above. Compare the live function
        // object against the request. Disagreement is a non-success
        // response naming the mismatched field.
        StringBuilder diff = new StringBuilder();
        if (returnType != null) {
            DataType actualRet = f.getReturnType();
            String actualName = (actualRet == null) ? "void" : actualRet.getName();
            if (!actualName.equals(returnType)) {
                diff.append("; returnType requested='").append(returnType)
                    .append("' stored='").append(actualName).append('\'');
            }
        }
        if (req.has("parameters") && req.get("parameters").isJsonArray()) {
            JsonArray reqParams = req.getAsJsonArray("parameters");
            for (int i = 0; i < reqParams.size(); i++) {
                JsonObject reqParam = reqParams.get(i).getAsJsonObject();
                String requestedName = RpcContext.optStr(reqParam, "name");
                if (requestedName == null || requestedName.isEmpty()) continue;
                // Map requested ordinal to stored parameter by ordinal.
                // The stored Function's ordinals match the request order
                // for DYNAMIC_STORAGE_* modes (the i-th requested param
                // becomes the i-th stored param).
                Parameter stored = (i < f.getParameterCount())
                    ? f.getParameter(i) : null;
                if (stored == null) {
                    diff.append("; parameters[").append(i).append("] requested name='")
                        .append(requestedName).append("' stored=(none)");
                    continue;
                }
                if (!requestedName.equals(stored.getName())) {
                    diff.append("; parameters[").append(i).append("] requested name='")
                        .append(requestedName).append("' stored='")
                        .append(stored.getName()).append('\'');
                }
            }
        }
        if (diff.length() > 0) {
            return RpcResponse.error(
                "UpdateFunctionCommand reported success but the live function object "
                + "does not reflect every requested edit" + diff
                + ". Ghidra's Function.updateFunction intermittently drops parts of "
                + "the request without raising an exception; re-issuing the same "
                + "command typically lands them. Verify with `function show --address "
                + f.getEntryPoint() + "` before trusting the result.");
        }
        return base;
    }
}
