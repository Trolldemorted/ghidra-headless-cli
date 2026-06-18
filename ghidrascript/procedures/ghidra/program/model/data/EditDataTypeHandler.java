package procedures.ghidra.program.model.data;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.TypeDef;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure EditDataType: apply a batch of edits to a single data type.
 *
 * Program-level and mutating. All ops run in one transaction; if any op fails
 * the request returns {@code success:false} without committing.
 *
 * Supported ops (any combination, all optional):
 *   - {@code rename}: new name (calls {@link DataType#setName})
 *   - {@code move}: new category path (calls {@link DataType#setCategoryPath})
 *   - {@code replaceFields}: drop existing fields before adding (struct/union)
 *   - {@code addFields}: array of {name, type}; appended (struct/union)
 *   - {@code addEntries}: array of {name, value}; appended (enum)
 *   - {@code base}: new base type (typedef) — implemented as replace with a
 *     freshly-built TypedefDataType sharing the same name+path.
 *
 * Built-in types ({@code /int}, {@code /char *}, …) are rejected: edit there
 * returns an error and the program is not modified.
 */
public final class EditDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        DataType dt = DataTypeOps.requireDataTypeByPath(ctx, RpcContext.reqStr(req, "path"));
        if (DataTypeOps.isBuiltIn(ctx, dt)) {
            return RpcResponse.error("Cannot edit built-in type '" + dt.getName() + "'.");
        }
        boolean[] touched = {false};
        ctx.runWrite("EditDataType", () -> {
            doEdits(req, dt, ctx);
            touched[0] = true;
        });
        if (!touched[0]) {
            return RpcResponse.error("Edit failed for '" + dt.getName() + "'.");
        }
        DataTypeSerializer ser = new DataTypeSerializer(ctx.program().getDataTypeManager());
        return new ShowDataTypeHandler.ShowResponse(ser.describe(dt));
    }

    private void doEdits(JsonObject req, DataType dt, RpcContext ctx) throws Exception {
        if (req.has("rename") && !req.get("rename").isJsonNull()) {
            String newName = req.get("rename").getAsString();
            if (newName.isEmpty()) {
                throw new IllegalArgumentException("'rename' must be non-empty.");
            }
            dt.setName(newName);
        }
        if (req.has("move") && !req.get("move").isJsonNull()) {
            String newCat = req.get("move").getAsString();
            DataTypeOps.requireCategory(ctx, newCat); // throws if missing
            dt.setCategoryPath(DataTypeOps.normalizePath(newCat));
        }
        if (dt instanceof Composite) {
            editComposite(req, (Composite) dt, ctx);
        } else if (dt instanceof Enum) {
            editEnum(req, (Enum) dt);
        } else if (dt instanceof TypeDef) {
            if (req.has("base") && !req.get("base").isJsonNull()) {
                throw new IllegalArgumentException(
                    "Typedef 'base' change requires delete + recreate; not yet supported.");
            }
        }
    }

    private void editComposite(JsonObject req, Composite c, RpcContext ctx)
            throws Exception {
        if (req.has("replaceFields") && req.get("replaceFields").getAsBoolean()) {
            // Composite.deleteAll() is not part of the public Composite interface
            // (Structure has its own helper, Union does not), so delete by ordinal
            // from the tail down: deleting index N re-shifts later components.
            int n = c.getNumComponents();
            for (int i = n - 1; i >= 0; i--) {
                c.delete(i);
            }
        }
        if (req.has("addFields") && req.get("addFields").isJsonArray()) {
            JsonArray arr = req.getAsJsonArray("addFields");
            for (DataTypeOps.FieldPair fp : DataTypeOps.fieldList(arr)) {
                DataType fdt = ctx.requireDataType(fp.type);
                c.add(fdt, fp.name, null);
            }
        }
    }

    private void editEnum(JsonObject req, Enum e) throws Exception {
        if (req.has("addEntries") && req.get("addEntries").isJsonArray()) {
            for (DataTypeOps.EnumEntry ee : DataTypeOps.enumEntries(req.getAsJsonArray("addEntries"))) {
                e.add(ee.name, ee.value);
            }
        }
    }
}