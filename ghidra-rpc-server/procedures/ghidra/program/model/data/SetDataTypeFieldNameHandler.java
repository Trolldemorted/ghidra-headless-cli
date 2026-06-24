package procedures.ghidra.program.model.data;

import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.TypeDef;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure SetDataTypeFieldName: rename a single struct or union field.
 * The field is addressed by {@code <name|@offset|N>} — see
 * {@link DataTypeOps#resolveFieldIndex}. The field's type, comment, and
 * offset are preserved; only the field's name string changes.
 *
 * <p>Type guard: the target must be a {@link Composite} (struct or
 * union). Typedefs, enums, pointers, arrays, etc. are rejected with a
 * message that points the caller at the underlying type. Built-ins
 * (e.g. {@code /byte}) are rejected because mutation of built-in
 * types does not persist meaningfully.
 *
 * <p>Underlying API: {@link DataTypeComponent#setFieldName(String)}.
 * Ghidra validates the name and throws {@code InvalidInputException}
 * for empty strings, names with forbidden characters (whitespace,
 * control chars, etc.), and names that collide with another field in
 * the same composite. The exception is caught and surfaced as a
 * normal {@code error} response.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class SetDataTypeFieldNameHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "path");
        String field = RpcContext.reqStr(req, "field");
        String newName = RpcContext.reqStr(req, "name");
        if (newName.isEmpty()) {
            return RpcResponse.error("'name' must be non-empty.");
        }

        DataType target = DataTypeOps.requireDataTypeByPath(ctx, path);
        if (DataTypeOps.isBuiltIn(ctx, target)) {
            return RpcResponse.error("Cannot edit built-in type '" + target.getName() + "'.");
        }
        if (!(target instanceof Composite)) {
            String hint = (target instanceof TypeDef)
                ? " Use `datatype show --path /" + target.getName() + "` to discover the underlying struct's path, then call set-field-name on that path."
                : "";
            return RpcResponse.error("Field renames are only supported on struct/union types; '"
                + path + "' is a " + target.getClass().getSimpleName() + "." + hint);
        }
        Composite composite = (Composite) target;
        if (composite.getNumComponents() == 0) {
            return RpcResponse.error("'" + path + "' has no fields to rename.");
        }

        int index = DataTypeOps.resolveFieldIndex(composite, field, path);

        // Read pre-mutation state. setFieldName returns a fresh
        // DataTypeComponent instance on success (the type and comment
        // on it are unchanged); capturing the old name here gives a
        // stable response.
        DataTypeComponent pre = composite.getComponent(index);
        final String prevName = pre.getFieldName();
        DataType currentType = pre.getDataType();
        final String currentTypePath = DataTypeSerializer.pathOf(currentType);
        final String currentComment = pre.getComment();

        final boolean[] ok = {false};
        try {
            ctx.runWrite("SetDataTypeFieldName", () -> {
                DataTypeComponent comp = composite.getComponent(index);
                comp.setFieldName(newName);
                ok[0] = true;
            });
        } catch (RuntimeException e) {
            // setFieldName wraps InvalidInputException in
            // RuntimeException (its signature is `throws
            // InvalidInputException` but the runWrite lambda can't
            // throw checked exceptions). Surface the message verbatim.
            Throwable cause = e.getCause();
            String msg = (cause != null && cause.getMessage() != null)
                ? cause.getMessage() : e.getMessage();
            return RpcResponse.error("renameField: " + msg);
        }
        if (!ok[0]) {
            return RpcResponse.error("Rename failed for field at index " + index
                + " of '" + path + "'.");
        }
        return new FieldNameResponse(path, newName, currentTypePath, currentComment, prevName);
    }

    /** Response shape; gson drops null fields. */
    static final class FieldNameResponse extends RpcResponse {
        final String path;
        final String field;
        final String type;
        final String comment;
        final String previous;

        FieldNameResponse(String path, String field, String type, String comment,
                String previous) {
            this.success = true;
            this.path = path;
            this.field = field;
            this.type = type;
            this.comment = comment;
            this.previous = previous;
        }
    }
}
