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
 * struct or union. The field is addressed by its zero-based index, by its
 * name (first match wins; an ambiguous name is an error), or by a
 * {@code @0xN} byte offset (structs only). Pass {@code comment: ""} to clear.
 *
 * <p>Type guard: the target must be a {@link Composite} (struct or union).
 * Typedefs, enums, pointers, arrays, etc. are rejected with a message that
 * points the caller at the underlying type. Built-ins (e.g. {@code /byte}) are
 * rejected because the comment would not persist meaningfully.
 *
 * <p>The new comment is applied inside one program transaction
 * ({@link RpcContext#runWrite}); the previous comment is returned alongside
 * the new value so callers can diff without re-querying. The field-index
 * resolver is shared with {@code SetDataTypeFieldType} and
 * {@code SetDataTypeFieldName} — see
 * {@link DataTypeOps#resolveFieldIndex}.
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

        int index = DataTypeOps.resolveFieldIndex(composite, field, path);

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
