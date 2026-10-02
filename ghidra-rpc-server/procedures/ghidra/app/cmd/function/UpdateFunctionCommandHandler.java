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
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

/**
 * Procedure UpdateFunctionCommand: update a function's calling convention,
 * return type, and/or parameter list. Each field is independently optional;
 * a field you leave out is left alone (see the presence-sensitivity note below).
 *
 * {@code updateType}: DYNAMIC_STORAGE_FORMAL_PARAMS (default), DYNAMIC_STORAGE_ALL_PARAMS,
 * or CUSTOM_STORAGE — applies to the parameter list, and is only meaningful
 * when {@code parameters} is present. {@code parameters}: [{name?, dataType}].
 * {@code force} overrides conflicting variable storage, likewise only on the
 * replace path.
 *
 * <p><b>{@code parameters} is presence-sensitive; the other fields are
 * "null means unchanged".</b> Ghidra's own contract is asymmetric
 * ({@code Function.updateFunction}, Function.java:406-429):
 * {@code callingConvention} and {@code returnValue} document {@code null}
 * as "no change required", but {@code newParams} is documented as
 * "Replace all current parameters with the given list". An empty list is
 * therefore <em>not</em> "leave alone" — it is "delete every parameter".
 *
 * <p>So this handler routes on whether {@code parameters} is present at all:
 * <ul>
 *   <li><b>present</b> (including an empty array) — full replace via
 *       {@link UpdateFunctionCommand}. An empty array is the explicit
 *       "clear the argument list" form, mirroring the
 *       {@code EditDataTypeHandler} contract.</li>
 *   <li><b>absent</b> — narrow path: {@code setCallingConvention} /
 *       {@code setReturnType} only, inside a single {@code runWrite}
 *       transaction. The existing parameter list is never reconstructed or
 *       rewritten, so omitting {@code --parameter} cannot drop parameters.</li>
 * </ul>
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
 * runs a verification pass after the write: it compares the requested
 * values against what the live {@link Function} actually returns and
 * attaches a {@code warning} describing any disagreement. The write has
 * already committed at that point (Ghidra has no rollback API for
 * {@code updateFunction}), so the failure is reported as a warning rather
 * than a non-success response — tripping the dispatcher's commit gate
 * would roll back an edit that already landed, which was worse than the
 * original silent-success bug.
 *
 * <p><b>Resulting signature.</b> Every response carries the signature as
 * it now stands, read back from the live function. Callers previously had
 * to issue a separate {@code ShowFunction} round-trip to see what landed —
 * which is how the parameter-loss regression went unnoticed.
 */
public final class UpdateFunctionCommandHandler implements RpcProcedure {

    /**
     * Response carrying the post-write signature. gson serializes the
     * subclass fields verbatim alongside {@code success}.
     */
    public static final class UpdateFunctionResponse extends RpcResponse {
        public String name;
        public String entryPoint;
        public String callingConvention;
        public String returnType;
        public List<ParamView> parameters;
    }

    /** One parameter of the resulting signature, as stored by Ghidra. */
    public static final class ParamView {
        public int ordinal;
        public String name;
        public String dataType;
        public String storage;

        ParamView(int ordinal, Parameter p) {
            this.ordinal = ordinal;
            this.name = p.getName();
            DataType dt = p.getDataType();
            this.dataType = (dt == null) ? "void" : dt.getName();
            this.storage = p.getVariableStorage().toString();
        }
    }

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

        // Both are optional on the wire. Ghidra documents null for each as
        // "no change required", so an absent key must not be an error.
        String callingConvention = RpcContext.optStr(req, "callingConvention");
        String returnType = RpcContext.optStr(req, "returnType");

        // Presence, not emptiness, decides the route -- see the class javadoc.
        boolean hasParams = req.has("parameters") && !req.get("parameters").isJsonNull();

        RpcResponse base;
        if (hasParams) {
            // Full replace. An empty array clears the argument list.
            Variable returnVar = (returnType == null)
                ? null : new ReturnParameterImpl(ctx.requireDataType(returnType), program);
            List<Variable> params = new ArrayList<>();
            for (JsonElement e : req.getAsJsonArray("parameters")) {
                JsonObject p = e.getAsJsonObject();
                params.add(new ParameterImpl(RpcContext.optStr(p, "name"),
                    ctx.requireDataType(RpcContext.reqStr(p, "dataType")), program, source));
            }
            boolean force = RpcContext.reqBool(req, "force");
            base = ctx.applyCommand(new UpdateFunctionCommand(
                f, updateType, callingConvention, returnVar, params, source, force));
            if (base == null || !base.success) {
                return base;
            }
        }
        else {
            // Narrow path: touch only what was passed. Parameters are left
            // exactly as stored. runWrite nests inside the dispatcher
            // transaction and rolls back on throw, so a rejected calling
            // convention cannot leave the return type half-applied.
            final Function target = f;
            final String cc = callingConvention;
            final String rt = returnType;
            final SourceType src = source;
            base = RpcResponse.ok();
            ctx.runWrite("UpdateFunctionCommand", () -> {
                if (cc != null) {
                    target.setCallingConvention(cc);
                }
                if (rt != null) {
                    target.setReturnType(ctx.requireDataType(rt), src);
                }
            });
        }

        // Verification pass — see Javadoc above. Compare the live function
        // object against the request. Disagreement is reported as a
        // `warning` on the success response (NOT a non-success error),
        // because the dispatcher treats success as the commit-and-checkin
        // gate: returning an error here would silently roll back the
        // edit that `applyCommand` already applied. Verified on 2026-08-06
        // #391 incident followup — the rollback was the worst part of
        // the verifier, worse than the original silent-success bug.
        //
        // Auto-`this` alignment: on `__thiscall` (and any other convention
        // whose prototype model has an auto-this slot), the stored
        // parameter list has one more entry than the request: the auto
        // `this` at ordinal 0. Naively indexing stored[i] against request[i]
        // shifts the diff by one and produces a guaranteed false positive
        // on every member function (verified deterministically on
        // 0x004B6B70). Detect the slot via
        // `stored.isAutoParameter() && stored.getAutoParameterType() ==
        // AutoParameterType.THIS` and offset stored index by 1 when it is
        // present.
        int storedOffset = 0;
        if (f.getParameterCount() > 0) {
            Parameter first = f.getParameter(0);
            if (first.isAutoParameter()
                && first.getAutoParameterType() == AutoParameterType.THIS) {
                storedOffset = 1;
            }
        }

        StringBuilder diff = new StringBuilder();
        if (callingConvention != null) {
            String actualCc = f.getCallingConventionName();
            if (!callingConvention.equals(actualCc)) {
                diff.append("; callingConvention requested='").append(callingConvention)
                    .append("' stored='").append(actualCc).append('\'');
            }
        }
        if (returnType != null) {
            DataType actualRet = f.getReturnType();
            String actualName = (actualRet == null) ? "void" : actualRet.getName();
            if (!actualName.equals(returnType)) {
                diff.append("; returnType requested='").append(returnType)
                    .append("' stored='").append(actualName).append('\'');
            }
        }
        // Only the full-replace path can disagree about parameters; on the
        // narrow path they were never touched, so there is nothing to check.
        if (hasParams) {
            JsonArray reqParams = req.getAsJsonArray("parameters");
            for (int i = 0; i < reqParams.size(); i++) {
                JsonObject reqParam = reqParams.get(i).getAsJsonObject();
                String requestedName = RpcContext.optStr(reqParam, "name");
                if (requestedName == null || requestedName.isEmpty()) continue;
                int storedIdx = i + storedOffset;
                Parameter stored = (storedIdx < f.getParameterCount())
                    ? f.getParameter(storedIdx) : null;
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
            base.warning = "UpdateFunctionCommand reported success at the Ghidra "
                + "layer but the live function object disagrees with the request "
                + "on at least one field" + diff
                + ". The edit IS committed and checked in (this is a warning, "
                + "not an error). The 2026-08-06 #391 incident noted that "
                + "re-issuing the same command can land the missing parts; verify "
                + "with `function show --address " + f.getEntryPoint() + "`.";
        }

        UpdateFunctionResponse out = new UpdateFunctionResponse();
        out.success = base.success;
        out.error = base.error;
        out.warning = base.warning;
        out.name = f.getName();
        out.entryPoint = f.getEntryPoint().toString();
        out.callingConvention = f.getCallingConventionName();
        DataType ret = f.getReturnType();
        out.returnType = (ret == null) ? "void" : ret.getName();
        out.parameters = new ArrayList<>();
        for (int i = 0; i < f.getParameterCount(); i++) {
            out.parameters.add(new ParamView(i, f.getParameter(i)));
        }
        return out;
    }
}
