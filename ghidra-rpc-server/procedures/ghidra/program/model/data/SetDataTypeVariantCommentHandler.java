package procedures.ghidra.program.model.data;

import java.util.Arrays;

import com.google.gson.JsonObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure SetDataTypeVariantComment: set the comment on a single enum
 * variant by name. Pass {@code comment: ""} to clear.
 *
 * <p><b>Ghidra API quirk:</b> {@link Enum} exposes no
 * {@code setComment(name, comment)} method — variants are
 * {@code (name, value, comment)} triples written via
 * {@link Enum#add(String, long, String)}. To change a comment we must
 * {@link Enum#remove(String) remove} the variant and re-{@link Enum#add add}
 * it. {@link Enum#getNames()} is sorted by value, not insertion order, so the
 * displayed order in the Data Type Manager is preserved across the round-trip
 * (assuming the new value matches the original, which we keep). Two variants
 * with the same value would lose insertion ordering — that is a malformed
 * enum and the API does not preserve it anyway.
 *
 * <p>Type guard: the target must be an {@link Enum}. Built-ins (e.g.
 * {@code /__stdcall__}) and other kinds (struct, union, typedef, pointer) are
 * rejected. If the requested variant name is not present we return an error
 * listing the first few existing names so the caller can correct the typo.
 */
public final class SetDataTypeVariantCommentHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "path");
        String variant = RpcContext.reqStr(req, "variant");
        // final so the runWrite lambda below can capture it; null -> "" clear.
        final String comment;
        {
            String c = RpcContext.optStr(req, "comment");
            comment = (c == null) ? "" : c;
        }

        DataType target = DataTypeOps.requireDataTypeByPath(ctx, path);
        if (DataTypeOps.isBuiltIn(ctx, target)) {
            return RpcResponse.error("Cannot edit built-in type '" + target.getName() + "'.");
        }
        if (!(target instanceof Enum)) {
            // TypedefDataType and other non-enum types are rejected
            // up front. For typedefs the variant storage is shared
            // with the underlying enum, so editing through the typedef
            // would silently change it for every consumer. Point the
            // caller at `datatype show --path /X` to discover the
            // underlying enum's path.
            String hint = (target instanceof ghidra.program.model.data.TypeDef)
                ? " Use `datatype show --path /" + target.getName() + "` to discover the underlying enum's path, then call set-variant-comment on that path."
                : "";
            return RpcResponse.error("Variant comments are only supported on enum types; '"
                + path + "' is a " + target.getClass().getSimpleName() + "." + hint);
        }
        Enum enumDt = (Enum) target;
        // Validate up front: if the variant doesn't exist, fail without
        // touching the DTM. Otherwise remove+add would silently drop an
        // unrequested variant and leave a zero-comment empty slot.
        if (!Arrays.asList(enumDt.getNames()).contains(variant)) {
            return RpcResponse.error("Variant '" + variant + "' not found in enum '" + path
                + "'. Available variants: " + availableVariants(enumDt));
        }

        long value = enumDt.getValue(variant);
        String previous = enumDt.getComment(variant);

        String[] applied = {null};
        ctx.runWrite("SetDataTypeVariantComment", () -> {
            // The per-program lock (RpcContext.lock) is held across the
            // whole request, so the up-front getNames() check above
            // cannot race with another mutation. remove+add is the only
            // way to set a variant comment because Enum has no
            // setComment(String, String) setter.
            enumDt.remove(variant);
            enumDt.add(variant, value, comment);
            applied[0] = enumDt.getComment(variant);
        });

        return new VariantCommentResponse(path, variant, applied[0], previous);
    }

    /** List up to 5 variant names for the not-found error message. */
    private static String availableVariants(Enum enumDt) {
        String[] names = enumDt.getNames();
        StringBuilder sb = new StringBuilder("[");
        int n = Math.min(5, names.length);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(names[i]);
        }
        if (names.length > 5) {
            sb.append(", ...");
        }
        sb.append(']');
        return sb.toString();
    }

    /** Response shape; gson drops null fields. */
    static final class VariantCommentResponse extends RpcResponse {
        final String path;
        final String variant;
        final String comment;
        final String previous;

        VariantCommentResponse(String path, String variant, String comment, String previous) {
            this.success = true;
            this.path = path;
            this.variant = variant;
            this.comment = comment;
            this.previous = previous;
        }
    }
}
