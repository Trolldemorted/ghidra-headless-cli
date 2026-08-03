package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.cmd.function.SetStackDepthChangeCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

/**
 * Procedure SetStackDepthChangeCommand: set the stack-depth-change value
 * at {@code address}.
 *
 * <p>The override is applied per call site and read by the decompiler via
 * {@code DecompileCallback.getExtraPopOverride}, which matches the
 * override address against flow references (the decompiler's
 * static-call-resolution path). <strong>Indirect calls — including vtable
 * dispatches like {@code CALL [EDX+0x54]} — have no flow references to
 * a concrete callee, so the override is stored but the decompiler will
 * never apply it.</strong> We detect that case up front and return a
 * clear error pointing at the limitation, instead of silently recording
 * a value that has no observable effect.
 *
 * <p><strong>Sign convention:</strong> {@code stackDepthChange} is the
 * delta in bytes the decompiler should add to its tracked stack depth
 * after the call (replaces the function's default {@code extrapop}).
 * Negative values are valid and common — they reduce the per-call depth
 * when the decompiler overestimates it.
 */
public final class SetStackDepthChangeCommandHandler implements RpcProcedure {
    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        int depthChange = RpcContext.reqInt(req, "stackDepthChange");
        String why = whyOverrideWouldNotApply(ctx, addr);
        if (why != null) {
            return RpcResponse.error(why
                + " The override would be stored but the decompiler never"
                + " applies stack-depth-change at indirect call sites (no"
                + " static callee). Use `get-depth-change` to verify a"
                + " stored override; use `remove-depth-change` to delete it.");
        }
        return ctx.applyCommand(new SetStackDepthChangeCommand(addr, depthChange));
    }

    /**
     * Return a non-null diagnostic if {@code addr} is a call-like
     * instruction with no flow references — i.e. an indirect call. The
     * decompiler's override-lookup only matches when there is a flow
     * reference to a known target. {@code null} means "no objection" —
     * the override can apply (or the address isn't a call at all and
     * the override is harmless garbage; the decompiler ignores those).
     */
    private static String whyOverrideWouldNotApply(RpcContext ctx, Address addr) {
        Instruction instr = ctx.program().getListing().getInstructionAt(addr);
        if (instr == null) {
            return null;
        }
        FlowType flow = instr.getFlowType();
        if (!flow.isCall()) {
            return null;
        }
        Reference[] refs = ctx.program().getReferenceManager()
            .getFlowReferencesFrom(addr);
        if (refs.length > 0) {
            return null;
        }
        Function func = ctx.program().getFunctionManager().getFunctionContaining(addr);
        String where = func != null
            ? " in function " + func.getName() + " @ " + func.getEntryPoint()
            : "";
        return "Call at " + addr + where + " has no flow references"
            + " (indirect call"
            + (flow.isUnConditional() ? "" : " / conditional")
            + ").";
    }
}