package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.AddStackVarCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

/**
 * Procedure AddStackVarCmd: add a stack variable to the function at
 * {@code address}.
 *
 * <p>{@code kind}: {@code param} (default) or {@code local}.
 * <ul>
 *   <li><b>{@code param}</b> routes to Ghidra's
 *       {@code AddStackVarCmd} — the historical path. It interprets
 *       {@code stackOffset >= 0} as a parameter slot in the caller's
 *       frame and {@code stackOffset < 0} as a local in the function's
 *       own frame (the x86 {@code EBP}/{@code RBP}-relative
 *       convention).</li>
 *   <li><b>{@code local}</b> bypasses {@code AddStackVarCmd} and
 *       constructs a {@link LocalVariableImpl} with the requested
 *       stack offset, then {@link Function#addLocalVariable(Variable,
 *       SourceType) addLocalVariable}s it. The offset is always
 *       interpreted as a function-local-frame-relative slot
 *       regardless of sign — what callers need when promoting a
 *       decompiler synthetic (e.g. {@code iStack_30}) at a positive
 *       offset in the local frame to a database-backed variable.
 *       {@code addLocalVariable} itself is atomic; we still wrap the
 *       call in {@code runWrite} so the per-file checkout/checkin
 *       flow is identical to the {@code param} path.</li>
 * </ul>
 */
public final class AddStackVarCmdHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address funcEntry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        int stackOffset = RpcContext.reqInt(req, "stackOffset");
        String name = RpcContext.optStr(req, "name");
        DataType dt = ctx.dataType(RpcContext.optStr(req, "dataType")); // null allowed
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        // `kind` is required on the wire (the CLI always sends it
        // explicitly so the server has an unambiguous contract — see
        // the [feedback: required fields on wire] memory note). Accept
        // "param" / "local" case-insensitively.
        String kind = RpcContext.reqStr(req, "kind").trim().toLowerCase();
        if (!"param".equals(kind) && !"local".equals(kind)) {
            return RpcResponse.error("Invalid 'kind' '" + kind
                + "': must be 'param' or 'local'.");
        }

        if ("local".equals(kind)) {
            return addLocal(ctx, funcEntry, stackOffset, name, dt, source);
        }
        return ctx.applyCommand(new AddStackVarCmd(
            funcEntry, stackOffset, name, dt, source));
    }

    /**
     * Add a function-local stack variable by constructing a
     * {@link LocalVariableImpl} and passing it to
     * {@link Function#addLocalVariable(Variable, SourceType)}.
     * {@code LocalVariableImpl}'s four-arg constructor
     * {@code (String, DataType, int, Program)} derives the
     * {@link ghidra.program.model.listing.VariableStorage} from the
     * signed stack offset, so the offset is always interpreted as a
     * function-local frame slot (positive or negative).
     */
    private static RpcResponse addLocal(RpcContext ctx, Address funcEntry, int stackOffset,
            String name, DataType dt, SourceType source) throws Exception {
        Function function = ctx.requireFunctionAt(funcEntry);
        Variable[] created = { null };
        String[] error = { null };
        ctx.runWrite("function variable add-stack --kind local " + funcEntry, () -> {
            try {
                // LocalVariableImpl clones the datatype into the program's
                // DTM so its length is resolved against the program's
                // type manager (the Javadoc warns that data-type length
                // can change after cloning, which would invalidate
                // pre-computed storage).
                LocalVariableImpl local = new LocalVariableImpl(
                    name, dt, stackOffset, ctx.program(), source);
                created[0] = function.addLocalVariable(local, source);
            } catch (Exception e) {
                error[0] = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            }
        });
        if (error[0] != null) {
            return RpcResponse.error(error[0]);
        }
        return RpcResponse.ok();
    }
}
