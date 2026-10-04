package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure CreateThunkFunctionCmd: create a thunk function at {@code address}. If
 * {@code referencedFunctionAddress} is given the thunk points there; otherwise the
 * thunked function is auto-detected.
 *
 * <p><b>Fall-through (adjustor) thunks.</b> Ghidra's own
 * {@code CreateThunkFunctionCmd.computeThunkBody} only accepts a body whose FIRST
 * instruction is a jump terminator, so it rejects the MSVC multiple-inheritance
 * adjustor {@code sub ecx, N; jmp target} with "Must specify thunk function
 * body" — an error that reads like a missing argument rather than a detection
 * failure. The engine is not the limitation: the same command has a constructor
 * taking an explicit {@code AddressSetView body}, which is the general case. So
 * when the caller names the referenced function we compute the body here — walk
 * forward from the entry through non-terminator instructions, then include the
 * terminating jump — and pass it in. The adjustment stays in the thunk's own
 * signature, which is where the decompiler reads it from.
 */
public final class CreateThunkFunctionCmdHandler implements RpcProcedure {

    /** Bound on the forward walk, so a non-thunk can't scan the whole listing. */
    private static final int MAX_BODY_INSTRUCTIONS = 16;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String refStr = RpcContext.optStr(req, "referencedFunctionAddress");
        CreateThunkFunctionCmd cmd;
        if (refStr != null) {
            Address ref = ctx.requireAddress(refStr);
            // An explicit `body` is what the GUI passes: the user's Listing
            // selection, handed to the same constructor CreateFunctionAction
            // uses. It is the only way to cover a thunk whose shape the
            // forward walk below does not model. Without one we derive the
            // body, which covers `jmp <t>` and `sub ecx,N; jmp <t>`.
            AddressSetView body = (req.has("body") && req.get("body").isJsonArray())
                ? ctx.addressSet(req)
                : computeBody(entry, ctx);
            if (body == null) {
                return RpcResponse.error("Cannot determine a thunk body at " + entry
                    + ": expected a jump terminator (JMP, or CALL/terminator) within "
                    + MAX_BODY_INSTRUCTIONS + " instructions, optionally preceded by "
                    + "non-terminating instructions such as `sub ecx, N`. "
                    + "Disassembly starts with: " + firstInstructions(entry, ctx)
                    + ". Pass --body START:END to state the body explicitly, the way "
                    + "the GUI takes it from the Listing selection.");
            }
            cmd = new CreateThunkFunctionCmd(entry, body, ref);
        } else {
            cmd = new CreateThunkFunctionCmd(entry, RpcContext.reqBool(req, "checkExisting"));
        }
        return ctx.applyCommand(cmd);
    }

    /**
     * Body for a thunk at {@code entry}: every instruction from the entry up to
     * and including the first jump terminator. Returns null when there is no
     * terminator within {@link #MAX_BODY_INSTRUCTIONS}, or when the entry does
     * not start on an instruction.
     *
     * <p>Terminator set mirrors Ghidra's own computeThunkBody so a bare JMP
     * thunk produces exactly the same body the engine would have computed.
     */
    private static AddressSet computeBody(Address entry, RpcContext ctx) {
        Listing listing = ctx.program().getListing();
        Instruction first = listing.getInstructionAt(entry);
        if (first == null) {
            return null;
        }
        AddressSet body = new AddressSet();
        Instruction instr = first;
        for (int i = 0; i < MAX_BODY_INSTRUCTIONS && instr != null; i++) {
            // Stop at a function boundary. An existing function starting here
            // may be short (a `ret` is not a jump terminator), and walking on
            // would claim addresses belonging to whatever follows it.
            Function other = listing.getFunctionContaining(instr.getMinAddress());
            if (other != null && !other.getEntryPoint().equals(entry)) {
                return null;
            }
            body.addRange(instr.getMinAddress(), instr.getMaxAddress());
            if (isTerminator(instr.getFlowType())) {
                return body;
            }
            instr = instr.getNext();
        }
        return null;
    }

    private static boolean isTerminator(FlowType flow) {
        return flow == RefType.UNCONDITIONAL_JUMP
            || flow == RefType.COMPUTED_JUMP
            || flow == RefType.COMPUTED_CALL_TERMINATOR
            || flow == RefType.CALL_TERMINATOR;
    }

    /** First few instructions at the entry, for the error message. */
    private static String firstInstructions(Address entry, RpcContext ctx) {
        Listing listing = ctx.program().getListing();
        StringBuilder sb = new StringBuilder();
        Instruction instr = listing.getInstructionAt(entry);
        for (int i = 0; i < 3 && instr != null; i++) {
            if (i > 0) {
                sb.append("; ");
            }
            sb.append(instr.toString());
            instr = instr.getNext();
        }
        return (sb.length() == 0) ? "<no instruction at " + entry + ">" : sb.toString();
    }
}
