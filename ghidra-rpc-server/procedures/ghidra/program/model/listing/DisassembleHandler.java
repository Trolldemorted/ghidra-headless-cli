package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.util.EolComments;
import ghidra.app.util.RefRepeatComment;
import ghidra.app.util.viewer.field.EolExtraCommentsOption;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CommentType;
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
        // `address` accepts either a hex address or an exact function name
        // (resolved via RpcContext.requireFunction).
        Function function = ctx.requireFunction(RpcContext.reqStr(req, "address"));
        boolean includeBytes = RpcContext.reqBool(req, "bytes");

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
                fmt.getRepresentationString(insn),
                renderEolComments(insn)));
        }

        return new DisassembleResponse(function.getName(),
            function.getEntryPoint().toString(), instructions.size(), instructions);
    }

    /** Disassembly does not change the program, so no check-in is required. */
    @Override
    public boolean mutates() {
        return false;
    }

    /**
     * Render the EOL column exactly as the GUI listing does, in the same
     * order {@code EolCommentFieldFactory} uses: the instruction's own EOL
     * comment, then a repeatable comment at the code unit, then — the one
     * that matters for readability — the <em>referenced</em> target's
     * repeatable comments, then auto comments.
     *
     * <p>The referenced case is why a repeatable comment set on a function
     * shows up on every {@code CALL} of it, which is the whole point of the
     * feature. The logic is not reimplemented: {@link EolComments} is Ghidra's
     * own resolver (the same class the listing widget drives), so this output
     * tracks the GUI's toggles and priorities instead of drifting from them.
     */
    private static List<String> renderEolComments(Instruction insn) {
        // operandsShowReferences=true: the representation column already
        // resolves operands, so suppress the duplicate auto-comment preview.
        EolComments comments = new EolComments(insn, true, 8, new EolExtraCommentsOption());
        List<String> out = new ArrayList<>();

        // The GUI listing gives pre its own column, left of the instruction.
        for (String s : insn.getCommentAsArray(CommentType.PRE)) {
            out.add("pre: " + s);
        }
        // ... and post its own column, right of the EOL column.
        for (String s : insn.getCommentAsArray(CommentType.POST)) {
            out.add("post: " + s);
        }
        // The plate comment is also its own column; on a function entry this
        // is the same storage as the function comment (see CommentOps).
        for (String s : insn.getCommentAsArray(CommentType.PLATE)) {
            out.add("plate: " + s);
        }

        // EOL column, in EolCommentFieldFactory's own order.
        for (String s : comments.getEOLComments()) {
            out.add(s);
        }
        if (comments.isShowingRepeatables()) {
            for (String s : comments.getRepeatableComments()) {
                out.add("repeatable: " + s);
            }
        }
        if (comments.isShowingRefRepeatables()) {
            for (RefRepeatComment r : comments.getReferencedRepeatableComments()) {
                String target = r.getAddress().toString();
                for (String line : r.getCommentLines()) {
                    out.add("repeatable@" + target + ": " + line);
                }
            }
        }
        if (comments.isShowingAutoComments()) {
            for (String s : comments.getAutomaticComment()) {
                out.add("auto: " + s);
            }
        }
        return out;
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
        /** EOL column, as the GUI listing renders it; empty when the row has none. */
        final List<String> comments;

        Insn(String address, String bytes, String mnemonic, String representation,
                List<String> comments) {
            this.address = address;
            this.bytes = bytes;
            this.mnemonic = mnemonic;
            this.representation = representation;
            this.comments = comments;
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
