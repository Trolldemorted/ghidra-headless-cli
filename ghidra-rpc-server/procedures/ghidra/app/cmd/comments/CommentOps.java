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
 * Five CodeUnit-level types (EOL/PRE/POST/REPEATABLE/PLATE) operate on the
 * {@link CodeUnit} at the given address via {@link CodeUnit#setComment} and
 * {@link CodeUnit#getComment}. The decompiler comment is function-level and
 * is stored on {@link Function#getComment} / {@link Function#setComment}; the
 * request address resolves to the containing function.
 *
 * For mutating calls (Set/Append/Clear) the CodeUnit path uses
 * {@link SetCommentCmd} / {@link AppendCommentCmd} so undo/redo works; the
 * function path runs inside a transaction via {@link RpcContext#runWrite}.
 */
final class CommentOps {

    /** Comment type enum mirrored to the wire (matches {@link CommentType#name()}). */
    enum Type {
        EOL(CommentType.EOL, false),
        PRE(CommentType.PRE, false),
        POST(CommentType.POST, false),
        REPEATABLE(CommentType.REPEATABLE, false),
        PLATE(CommentType.PLATE, false),
        DECOMPILER(null, true);

        final CommentType cuType;
        final boolean functionLevel;

        Type(CommentType cuType, boolean functionLevel) {
            this.cuType = cuType;
            this.functionLevel = functionLevel;
        }
    }

    /** Read the comment at the address. */
    static RpcResponse get(Address addr, Type type, RpcContext ctx) {
        if (type.functionLevel) {
            Function fn = ctx.program().getFunctionManager().getFunctionContaining(addr);
            if (fn == null) {
                return RpcResponse.error("No function contains address " + addr + ".");
            }
            return new CommentResponse(type.name(), addr, fn.getName(), fn.getComment());
        }
        CodeUnit cu = ctx.program().getListing().getCodeUnitAt(addr);
        if (cu == null) {
            return RpcResponse.error("No code unit at address " + addr + ".");
        }
        return new CommentResponse(type.name(), addr, null, cu.getComment(type.cuType));
    }

    /** Set the comment at the address (empty string clears it). */
    static RpcResponse set(Address addr, Type type, String text, RpcContext ctx) throws Exception {
        if (type.functionLevel) {
            Function fn = requireFunction(addr, ctx);
            String previous = fn.getComment();
            String[] result = {previous};
            ctx.runWrite("Set " + type + " Comment", () -> {
                fn.setComment(text == null ? "" : text);
                result[0] = fn.getComment();
            });
            return new CommentResponse(type.name(), addr, fn.getName(), result[0], previous);
        }
        CodeUnit cu = requireCodeUnit(addr, ctx);
        String previous = cu.getComment(type.cuType);
        RpcResponse r = ctx.applyCommand(
            new SetCommentCmd(addr, type.cuType, text == null ? "" : text));
        if (!r.success) return r;
        return new CommentResponse(type.name(), addr, null, cu.getComment(type.cuType), previous);
    }

    /** Append text to the existing comment, separated by {@code separator} (default newline). */
    static RpcResponse append(Address addr, Type type, String text, String separator,
            RpcContext ctx) throws Exception {
        String sep = (separator == null || separator.isEmpty()) ? "\n" : separator;
        if (type.functionLevel) {
            Function fn = requireFunction(addr, ctx);
            String previous = fn.getComment();
            String[] result = {previous};
            ctx.runWrite("Append " + type + " Comment", () -> {
                String combined = previous == null || previous.isEmpty()
                    ? text : previous + sep + text;
                fn.setComment(combined);
                result[0] = fn.getComment();
            });
            return new CommentResponse(type.name(), addr, fn.getName(), result[0], previous);
        }
        CodeUnit cu = requireCodeUnit(addr, ctx);
        String previous = cu.getComment(type.cuType);
        RpcResponse r = ctx.applyCommand(
            new AppendCommentCmd(addr, type.cuType, text, sep));
        if (!r.success) return r;
        return new CommentResponse(type.name(), addr, null, cu.getComment(type.cuType), previous);
    }

    /** Clear the comment at the address (set it to empty string). */
    static RpcResponse clear(Address addr, Type type, RpcContext ctx) throws Exception {
        return set(addr, type, "", ctx);
    }

    private static CodeUnit requireCodeUnit(Address addr, RpcContext ctx) {
        CodeUnit cu = ctx.program().getListing().getCodeUnitAt(addr);
        if (cu == null) {
            throw new IllegalArgumentException("No code unit at address " + addr + ".");
        }
        return cu;
    }

    private static Function requireFunction(Address addr, RpcContext ctx) {
        Function fn = ctx.program().getFunctionManager().getFunctionContaining(addr);
        if (fn == null) {
            throw new IllegalArgumentException("No function contains address " + addr + ".");
        }
        return fn;
    }

    /** Common response shape; gson drops null fields. */
    static final class CommentResponse extends RpcResponse {
        final String type;
        final String address;
        final String function;   // function-level only (DECOMPILER)
        final String comment;
        final String previous;   // mutating ops only

        CommentResponse(String type, Address address, String function, String comment) {
            this(type, address, function, comment, null);
        }

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