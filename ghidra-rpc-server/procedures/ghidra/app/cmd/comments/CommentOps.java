package procedures.ghidra.app.cmd.comments;

import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;

import procedures.RpcContext;
import procedures.RpcResponse;

/**
 * Shared logic for the comment subcommands.
 *
 * Five types (EOL/PRE/POST/REPEATABLE/PLATE) operate on the {@link CodeUnit}
 * at the given address, named as in the GUI's "Comments" menu ("Set EOL
 * Comment...", "Set Pre Comment...", ...).
 *
 * DECOMPILER is not a storage type. It does what "Comments &gt; Set..."
 * (the {@code ;} key) does in the GUI's Decompiler window
 * ({@code DecompilerCommentsActionFactory.DecompilerEditCommentsAction}):
 * <ul>
 *   <li>at a function's entry point it edits the <b>Plate Comment</b>, which
 *       the decompiler prints as the function's header comment;</li>
 *   <li>at any other address inside a function it edits the <b>Pre
 *       Comment</b> of the code unit containing that address, which the
 *       decompiler prints above the matching statement.</li>
 * </ul>
 * The response's {@code type} names the comment that was actually touched
 * (PLATE or PRE) and {@code address} the code unit it is stored on.
 *
 * Mutating calls use {@link SetCommentCmd} / {@link AppendCommentCmd}, the
 * same commands the GUI dialog issues.
 */
final class CommentOps {

    /** Comment type enum mirrored to the wire (matches {@link CommentType#name()}). */
    enum Type {
        EOL(CommentType.EOL),
        PRE(CommentType.PRE),
        POST(CommentType.POST),
        REPEATABLE(CommentType.REPEATABLE),
        PLATE(CommentType.PLATE),
        /** Decompiler-window comment: PLATE at a function entry, PRE elsewhere. */
        DECOMPILER(null);

        final CommentType cuType;

        Type(CommentType cuType) {
            this.cuType = cuType;
        }
    }

    /** A request resolved to the concrete comment slot it operates on. */
    private static final class Target {
        final Address addr;
        final Type type;
        final String function;   // set for DECOMPILER requests only
        final CodeUnit cu;

        Target(Address addr, Type type, String function, CodeUnit cu) {
            this.addr = addr;
            this.type = type;
            this.function = function;
            this.cu = cu;
        }

        String current() {
            return cu.getComment(type.cuType);
        }

        CommentResponse response(String previous) {
            return new CommentResponse(type.name(), addr, function, current(), previous);
        }
    }

    private static Target resolve(Address addr, Type type, RpcContext ctx) {
        if (type != Type.DECOMPILER) {
            return new Target(addr, type, null, requireCodeUnit(addr, ctx));
        }
        Function fn = ctx.program().getFunctionManager().getFunctionContaining(addr);
        if (fn == null) {
            throw new IllegalArgumentException("No function contains address " + addr
                + "; the decompiler only shows comments inside a function.");
        }
        if (addr.equals(fn.getEntryPoint())) {
            return new Target(addr, Type.PLATE, fn.getName(), requireCodeUnit(addr, ctx));
        }
        // Like the GUI dialog, comment the code unit the address falls in.
        CodeUnit cu = ctx.program().getListing().getCodeUnitContaining(addr);
        if (cu == null) {
            throw new IllegalArgumentException("No code unit at address " + addr + ".");
        }
        return new Target(cu.getMinAddress(), Type.PRE, fn.getName(), cu);
    }

    /** Read the comment at the address. */
    static RpcResponse get(Address addr, Type type, RpcContext ctx) {
        return resolve(addr, type, ctx).response(null);
    }

    /**
     * Set the comment at the address. A null or empty {@code text} REMOVES the
     * comment: Ghidra distinguishes a null comment (no record) from an empty
     * one (a record holding ""), and storing "" left a phantom comment behind
     * that made a later append start with the separator and pushed a new
     * repository version for a no-op clear.
     */
    static RpcResponse set(Address addr, Type type, String rawText, RpcContext ctx) throws Exception {
        final String text = (rawText == null || rawText.isEmpty()) ? null : rawText;
        Target t = resolve(addr, type, ctx);
        String previous = t.current();
        RpcResponse r = ctx.applyCommand(new SetCommentCmd(t.addr, t.type.cuType, text));
        if (!r.success) return r;
        return t.response(previous);
    }

    /** Append text to the existing comment, separated by {@code separator} (default newline). */
    static RpcResponse append(Address addr, Type type, String text, String separator,
            RpcContext ctx) throws Exception {
        String sep = (separator == null || separator.isEmpty()) ? "\n" : separator;
        Target t = resolve(addr, type, ctx);
        String previous = t.current();
        RpcResponse r = ctx.applyCommand(new AppendCommentCmd(t.addr, t.type.cuType, text, sep));
        if (!r.success) return r;
        return t.response(previous);
    }

    /** Clear (remove) the comment at the address. */
    static RpcResponse clear(Address addr, Type type, RpcContext ctx) throws Exception {
        return set(addr, type, null, ctx);
    }

    private static CodeUnit requireCodeUnit(Address addr, RpcContext ctx) {
        CodeUnit cu = ctx.program().getListing().getCodeUnitAt(addr);
        if (cu == null) {
            throw new IllegalArgumentException("No code unit at address " + addr + ".");
        }
        return cu;
    }

    /** Common response shape; gson drops null fields. */
    static final class CommentResponse extends RpcResponse {
        final String type;
        final String address;
        final String function;   // Decompiler* procedures only
        final String comment;
        final String previous;   // mutating ops only

        CommentResponse(String type, Address address, String function, String comment,
                String previous) {
            this.success = true;
            this.type = type;
            this.address = address.toString();
            this.function = function;
            this.comment = comment;
            this.previous = previous;
        }
    }
}