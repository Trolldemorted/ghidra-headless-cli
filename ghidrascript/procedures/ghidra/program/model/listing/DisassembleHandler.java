package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Procedure Disassemble: return the instruction listing of the function at
 * {@code address}.
 *
 * Iterates the function body's instructions in address order
 * ({@link Listing#getInstructions(ghidra.program.model.address.AddressSetView, boolean)} —
 * the body may span several ranges; the iterator covers them all) and renders each
 * with {@link CodeUnitFormat#DEFAULT}, which resolves operand references the way the
 * GUI listing does (e.g. {@code CALL FUN_004100b0}).
 *
 * Read-only: like FlatDecompilerAPI this never modifies the program, so
 * {@link #mutates()} is false and the file is not checked in (dispatch still checks it
 * out, per policy).
 */
public final class DisassembleHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Function function = ctx.requireFunctionAt(RpcContext.reqStr(req, "address"));
        boolean includeBytes = RpcContext.optBool(req, "bytes", true);

        Listing listing = ctx.program().getListing();
        CodeUnitFormat fmt = CodeUnitFormat.DEFAULT;

        // Instructions only (data/undefined units in the body are skipped). An external
        // or not-yet-disassembled function simply yields an empty list -> count 0.
        List<Insn> instructions = new ArrayList<>();
        for (Instruction insn : listing.getInstructions(function.getBody(), true)) {
            ctx.monitor().checkCancelled();
            String bytes = null;
            if (includeBytes) {
                try {
                    bytes = toHex(insn.getBytes());
                } catch (MemoryAccessException e) {
                    bytes = null; // uninitialized memory: omit bytes for this line
                }
            }
            instructions.add(new Insn(
                insn.getMinAddress().toString(),
                bytes,
                insn.getMnemonicString(),
                fmt.getRepresentationString(insn)));
        }

        return new DisassembleResponse(function.getName(),
            function.getEntryPoint().toString(), instructions.size(), instructions);
    }

    /** Disassembly does not change the program, so no check-in is required. */
    @Override
    public boolean mutates() {
        return false;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    /** One disassembled instruction; serialized by gson (null {@code bytes} omitted). */
    static final class Insn {
        final String address;
        final String bytes;
        final String mnemonic;
        final String representation;

        Insn(String address, String bytes, String mnemonic, String representation) {
            this.address = address;
            this.bytes = bytes;
            this.mnemonic = mnemonic;
            this.representation = representation;
        }
    }

    /** Success response carrying the function's instruction listing. */
    static final class DisassembleResponse extends RpcResponse {
        final String function;
        final String address;
        final int count;
        final List<Insn> instructions;

        DisassembleResponse(String function, String address, int count, List<Insn> instructions) {
            this.success = true;
            this.function = function;
            this.address = address;
            this.count = count;
            this.instructions = instructions;
        }
    }
}
