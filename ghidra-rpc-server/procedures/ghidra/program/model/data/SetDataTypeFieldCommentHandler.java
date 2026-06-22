package procedures.ghidra.program.model.data;

import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure SetDataTypeFieldComment: set the comment on a single field of a
 * struct or union. The field is addressed either by its zero-based index or by
 * its name (first match wins; an ambiguous name is an error). Pass
 * {@code comment: ""} to clear.
 *
 * <p>Type guard: the target must be a {@link Composite} (struct or union).
 * Typedefs, enums, pointers, arrays, etc. are rejected with a message that
 * points the caller at the underlying type. Built-ins (e.g. {@code /byte}) are
 * rejected because the comment would not persist meaningfully.
 *
 * <p>The new comment is applied inside one program transaction
 * ({@link RpcContext#runWrite}); the previous comment is returned alongside
 * the new value so callers can diff without re-querying.
 */
public final class SetDataTypeFieldCommentHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "path");
        String field = RpcContext.reqStr(req, "field");
        // comment is optional; null/empty both clear. Normalize null -> "" so
        // the success path always has a non-null value to echo back.
        final String comment;  // final so the runWrite lambda can capture it
        {
            String c = RpcContext.optStr(req, "comment");
            comment = (c == null) ? "" : c;
        }

        DataType target = DataTypeOps.requireDataTypeByPath(ctx, path);
        if (DataTypeOps.isBuiltIn(ctx, target)) {
            return RpcResponse.error("Cannot edit built-in type '" + target.getName() + "'.");
        }
        if (!(target instanceof Composite)) {
            // TypedefDataType and other non-composite types are rejected
            // up front. For typedefs the field storage is shared with
            // the underlying struct, so editing through the typedef
            // would silently change it for every consumer. Point the
            // caller at `datatype show --path /X` to discover the
            // underlying struct's path.
            String hint = (target instanceof ghidra.program.model.data.TypeDef)
                ? " Use `datatype show --path /" + target.getName() + "` to discover the underlying struct's path, then call set-field-comment on that path."
                : "";
            return RpcResponse.error("Field comments are only supported on struct/union types; '"
                + path + "' is a " + target.getClass().getSimpleName() + "." + hint);
        }
        Composite composite = (Composite) target;
        if (composite.getNumComponents() == 0) {
            return RpcResponse.error("'" + path + "' has no fields to comment.");
        }

        int index = resolveFieldIndex(composite, field, path);

        // Capture the field name BEFORE the setComment call: Ghidra's
        // DataTypeComponent.setComment returns a new DataTypeComponent
        // instance, but getFieldName is unchanged on it. Capturing here
        // makes the response stable even if Ghidra's internals change.
        String fieldName = composite.getComponent(index).getFieldName();
        String previous = composite.getComponent(index).getComment();

        final String[] applied = {null};
        ctx.runWrite("SetDataTypeFieldComment", () -> {
            DataTypeComponent comp = composite.getComponent(index);
            comp.setComment(comment);
            applied[0] = comp.getComment();
        });

        return new FieldCommentResponse(path, fieldName, applied[0], previous);
    }

    /**
     * Map the user-supplied {@code field} specifier to a component index.
     * All-digits and positive -> literal index (after bounds check). Anything
     * else -> name search; first match wins. An ambiguous name is an error
     * so the caller can disambiguate by index.
     */
    private static int resolveFieldIndex(Composite composite, String field, String path) {
        Integer asIndex = tryParseIndex(field);
        if (asIndex != null) {
            int n = composite.getNumComponents();
            if (asIndex < 0 || asIndex >= n) {
                throw new IllegalArgumentException("Field index " + asIndex
                    + " out of range for '" + path + "' (valid: 0.." + (n - 1) + ").");
            }
            return asIndex;
        }
        int match = -1;
        for (int i = 0; i < composite.getNumComponents(); i++) {
            DataTypeComponent c = composite.getComponent(i);
            if (c == null) continue;
            if (field.equals(c.getFieldName())) {
                if (match != -1) {
                    throw new IllegalArgumentException("Field name '" + field
                        + "' is ambiguous in '" + path + "' (matches at least indices "
                        + match + " and " + i + "); use the index instead.");
                }
                match = i;
            }
        }
        if (match == -1) {
            throw new IllegalArgumentException("Field '" + field + "' not found in '" + path
                + "'. Available fields: " + availableFields(composite));
        }
        return match;
    }

    /** Parse a positive integer string; null if not a clean non-negative int. */
    private static Integer tryParseIndex(String s) {
        if (s == null || s.isEmpty() || s.length() > 9) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
        }
        try {
            int n = Integer.parseInt(s);
            return n >= 0 ? n : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** List up to 5 field names for the not-found / ambiguous error message. */
    private static String availableFields(Composite composite) {
        StringBuilder sb = new StringBuilder("[");
        int n = Math.min(5, composite.getNumComponents());
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            DataTypeComponent c = composite.getComponent(i);
            String name = c == null ? "?" : c.getFieldName();
            sb.append(name == null ? "(unnamed)" : name);
        }
        if (composite.getNumComponents() > 5) {
            sb.append(", ...");
        }
        sb.append(']');
        return sb.toString();
    }

    /** Response shape; gson drops null fields. */
    static final class FieldCommentResponse extends RpcResponse {
        final String path;
        final String field;
        final String comment;
        final String previous;

        FieldCommentResponse(String path, String field, String comment, String previous) {
            this.success = true;
            this.path = path;
            this.field = field;
            this.comment = comment;
            this.previous = previous;
        }
    }
}
