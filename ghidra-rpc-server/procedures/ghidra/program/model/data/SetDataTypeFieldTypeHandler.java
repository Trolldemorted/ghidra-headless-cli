package procedures.ghidra.program.model.data;

import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure SetDataTypeFieldType: replace a single struct or union field's
 * type in place. The field is addressed by {@code <name|@offset|N>} — see
 * {@link DataTypeOps#resolveFieldIndex}. The field name, the field comment,
 * and every other field are preserved.
 *
 * <p>Length policy (default strict-equal): the new type's
 * {@link DataType#getLength()} must equal the existing component's length.
 * On mismatch, the call is rejected with a message that names both
 * lengths and points the caller at the {@code force} flag. When
 * {@code force=true}, the underlying {@link Structure#replace} slow path
 * runs — the struct may grow or shrink, and trailing components may
 * shift (their offsets are updated to match the new layout; comments
 * on the shifted components are preserved by Ghidra's repack).
 *
 * <p>Struct vs union: structs use
 * {@link Structure#replace(int, DataType, int, String, String)} (the
 * 5-arg form is the only one that takes a name+comment and the only
 * one that does not silently clear the existing comment — verified
 * via {@code DataTypeComponentDB.update} bytecode, which calls
 * {@code setString(4, comment)} unconditionally). Unions have no
 * {@code replace} API, so the union path is {@link Composite#delete}
 * + {@link Composite#insert} at the same ordinal.
 *
 * <p>Type guard: the target must be a {@link Composite} (struct or
 * union). Typedefs, enums, pointers, arrays, etc. are rejected with a
 * message that points the caller at the underlying type. Built-ins
 * (e.g. {@code /byte}) are rejected because mutation of built-in
 * types does not persist meaningfully.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class SetDataTypeFieldTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "path");
        String field = RpcContext.reqStr(req, "field");
        String typeSpec = RpcContext.reqStr(req, "type");
        boolean force = RpcContext.optBool(req, "force", false);

        DataType target = DataTypeOps.requireDataTypeByPath(ctx, path);
        if (DataTypeOps.isBuiltIn(ctx, target)) {
            return RpcResponse.error("Cannot edit built-in type '" + target.getName() + "'.");
        }
        if (!(target instanceof Composite)) {
            // Typedef/Enum/Array/Pointer — reject. For typedefs the
            // field storage is shared with the underlying struct, so
            // editing through the typedef would silently change it for
            // every consumer. Point the caller at `datatype show
            // --path /X` to discover the underlying struct's path.
            String hint = (target instanceof TypeDef)
                ? " Use `datatype show --path /" + target.getName() + "` to discover the underlying struct's path, then call set-field-type on that path."
                : "";
            return RpcResponse.error("Field retypes are only supported on struct/union types; '"
                + path + "' is a " + target.getClass().getSimpleName() + "." + hint);
        }
        Composite composite = (Composite) target;
        if (composite.getNumComponents() == 0) {
            return RpcResponse.error("'" + path + "' has no fields to retype.");
        }

        int index = DataTypeOps.resolveFieldIndex(composite, field, path);

        // Read pre-mutation state BEFORE the runWrite lambda. Ghidra's
        // setName / setComment / setFieldName on DataTypeComponent may
        // return a fresh DataTypeComponent instance; capturing the old
        // values here gives a stable response even if Ghidra's internals
        // change. We need the prev name + comment to pass them back into
        // Structure.replace's 5-arg form (which would otherwise clear the
        // comment — see class Javadoc).
        DataTypeComponent pre = composite.getComponent(index);
        final String prevFieldName = pre.getFieldName();
        final int prevLength = pre.getLength();
        final String prevTypePath = DataTypeSerializer.pathOf(pre.getDataType());
        final String prevComment = pre.getComment();
        if (prevFieldName == null) {
            // An unnamed component can't be retyped because the 5-arg
            // Structure.replace would set its name to "" (which Ghidra
            // normalizes to "(unnamed)" but is still a visible change).
            // Force the caller to give the field a real name first via
            // set-field-name.
            return RpcResponse.error("Field at index " + index + " of '" + path
                + "' is unnamed; give it a real name first with `set-field-name`.");
        }

        // Resolve the new type OUTSIDE the transaction. If the new type
        // doesn't resolve, the DTM is untouched (no transaction has
        // opened). requireDataType accepts a C-syntax expression
        // (e.g. "int", "char *", "byte[16]") or a full path
        // (e.g. "/MyCat/MyStruct") — same as EditDataType.
        final DataType newType;
        try {
            newType = ctx.requireDataType(typeSpec);
        } catch (IllegalArgumentException e) {
            return RpcResponse.error(e.getMessage());
        }
        final int newLength = newType.getLength();

        // Strict-length check. Without --force, the new type's length
        // must equal the existing component's length exactly. This is
        // the conservative default — same-size retype never shifts
        // trailing components and preserves every offset. Use --force
        // when the structural change is intentional.
        if (!force && newLength != prevLength) {
            return RpcResponse.error("New type '" + (newType.getPathName() != null
                ? newType.getPathName() : newType.getName()) + "' (length " + newLength
                + ") does not match existing component length " + prevLength
                + " at field '" + prevFieldName + "' (index " + index + ") of '" + path
                + "'. Retype requires identical length; pass force=true to allow "
                + "grow/shrink (may shift trailing components).");
        }

        final String newTypePath = DataTypeSerializer.pathOf(newType);
        final String[] appliedComment = {prevComment};
        final boolean[] ok = {false};
        ctx.runWrite("SetDataTypeFieldType", () -> {
            if (composite instanceof Structure) {
                // 5-arg replace: index, newType, newLength, newFieldName,
                // newComment. Pass the existing name + comment back to
                // preserve them — see class Javadoc.
                DataTypeComponent after = ((Structure) composite).replace(
                    index, newType, newLength, prevFieldName, prevComment);
                if (after == null) {
                    throw new RuntimeException("Structure.replace returned null at index "
                        + index + " of '" + path + "'.");
                }
                appliedComment[0] = after.getComment();
            } else if (composite instanceof Union) {
                // Union has no replace() — use delete+insert. delete(int)
                // shifts subsequent indices downward; we delete+insert at
                // the same index so the net result is the same ordinal
                // for the new component.
                composite.delete(index);
                DataTypeComponent after = composite.insert(
                    index, newType, newLength, prevFieldName, prevComment);
                if (after == null) {
                    throw new RuntimeException("Union.insert returned null at index "
                        + index + " of '" + path + "'.");
                }
                appliedComment[0] = after.getComment();
            } else {
                // Defensive — composite was confirmed instanceof Composite
                // above, and the only Concrete subtypes are Structure and
                // Union. Anything else is a Ghidra internal change; fail
                // loudly so the user can report it.
                throw new RuntimeException("Composite subtype "
                    + composite.getClass().getSimpleName()
                    + " is not supported by set-field-type (path='" + path + "').");
            }
            ok[0] = true;
        });
        if (!ok[0]) {
            return RpcResponse.error("Retype failed for field '" + prevFieldName
                + "' of '" + path + "'.");
        }
        return new FieldTypeResponse(path, prevFieldName, newTypePath, newLength,
            appliedComment[0], prevTypePath, prevLength, prevComment, force);
    }

    /** Response shape; gson drops null fields. */
    static final class FieldTypeResponse extends RpcResponse {
        final String path;
        final String field;
        final String type;
        final int typeLength;
        final String comment;
        final String previousType;
        final int previousLength;
        final String previousComment;
        final boolean forced;

        FieldTypeResponse(String path, String field, String type, int typeLength,
                String comment, String previousType, int previousLength,
                String previousComment, boolean forced) {
            this.success = true;
            this.path = path;
            this.field = field;
            this.type = type;
            this.typeLength = typeLength;
            this.comment = comment;
            this.previousType = previousType;
            this.previousLength = previousLength;
            this.previousComment = previousComment;
            this.forced = forced;
        }
    }
}
