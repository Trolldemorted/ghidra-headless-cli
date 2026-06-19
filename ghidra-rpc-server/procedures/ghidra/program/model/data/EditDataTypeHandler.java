package procedures.ghidra.program.model.data;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.TypeDef;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure EditDataType: apply a batch of edits to a single data type.
 *
 * All ops run in one transaction; if any op fails the entire batch rolls back.
 *
 * <p>{@code definition} (a C snippet) is the most powerful op: it parses a
 * new type and {@link DataTypeConflictHandler#REPLACE_HANDLER replaces} the
 * existing type in place. References in function signatures, applied data,
 * and other types are preserved (REPLACE is in-place, not delete+create).
 * The snippet's name is auto-set to the target's path so anonymous snippets
 * round-trip. {@code rename} and {@code move} can still be applied alongside
 * {@code definition} — they happen before the body is replaced.
 */
public final class EditDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        DataType target = DataTypeOps.requireDataTypeByPath(ctx, RpcContext.reqStr(req, "path"));
        if (DataTypeOps.isBuiltIn(ctx, target)) {
            return RpcResponse.error("Cannot edit built-in type '" + target.getName() + "'.");
        }

        String defn = RpcContext.optStr(req, "definition");
        if (defn != null && !defn.isEmpty()) {
            // Parse the snippet directly into the program DTM. CParser
            // requires a named snippet; the parsed type's name must equal
            // the target's so REPLACE_HANDLER can swap it in place.
            DataType parsed;
            try {
                parsed = CDefinitionParser.parse(defn,
                    ctx.program().getDataTypeManager());
            } catch (IllegalArgumentException e) {
                return RpcResponse.error(e.getMessage());
            }
            if (!sameKind(target, parsed)) {
                return RpcResponse.error("C snippet kind '" + kindName(parsed)
                    + "' does not match target '" + target.getName() + "'.");
            }
            if (!parsed.getName().equals(target.getName())) {
                return RpcResponse.error("C snippet name '" + parsed.getName()
                    + "' does not match target '" + target.getName()
                    + "'. The snippet must declare the target's name "
                    + "(e.g. `struct " + target.getName() + " { ... };`).");
            }
            boolean[] touched = {false};
            ctx.runWrite("EditDataType", () -> {
                doEdits(req, target, ctx);                  // rename, move first
                ctx.program().getDataTypeManager().addDataType(parsed,
                    DataTypeConflictHandler.REPLACE_HANDLER);
                touched[0] = true;
            });
            if (!touched[0]) return RpcResponse.error("Edit failed for '" + target.getName() + "'.");
            return new ShowDataTypeHandler.ShowResponse(
                ctx.program().getDataTypeManager(), target);
        }

        // Explicit-JSON path: rename / move / replaceFields / addFields / addEntries.
        boolean[] touched = {false};
        ctx.runWrite("EditDataType", () -> {
            doEdits(req, target, ctx);
            touched[0] = true;
        });
        if (!touched[0]) return RpcResponse.error("Edit failed for '" + target.getName() + "'.");
        return new ShowDataTypeHandler.ShowResponse(
            ctx.program().getDataTypeManager(), target);
    }

    private static boolean sameKind(DataType a, DataType b) {
        if (a instanceof Composite) return b instanceof Composite;
        if (a instanceof Enum) return b instanceof Enum;
        if (a instanceof TypeDef) return b instanceof TypeDef;
        return a.getClass().equals(b.getClass());
    }

    private static String kindName(DataType dt) {
        if (dt instanceof Composite) {
            return dt instanceof ghidra.program.model.data.Union ? "union" : "struct";
        }
        if (dt instanceof Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        return dt.getClass().getSimpleName();
    }

    private void doEdits(JsonObject req, DataType dt, RpcContext ctx) throws Exception {
        if (req.has("rename") && !req.get("rename").isJsonNull()) {
            String newName = req.get("rename").getAsString();
            if (newName.isEmpty()) throw new IllegalArgumentException("'rename' must be non-empty.");
            dt.setName(newName);
        }
        if (req.has("move") && !req.get("move").isJsonNull()) {
            String newCat = req.get("move").getAsString();
            DataTypeOps.requireCategory(ctx, newCat);
            dt.setCategoryPath(DataTypeOps.normalizePath(newCat));
        }
        if (dt instanceof Composite) {
            Composite c = (Composite) dt;
            if (req.has("replaceFields") && req.get("replaceFields").getAsBoolean()) {
                for (int i = c.getNumComponents() - 1; i >= 0; i--) c.delete(i);
            }
            if (req.has("addFields") && req.get("addFields").isJsonArray()) {
                JsonArray arr = req.getAsJsonArray("addFields");
                for (DataTypeOps.FieldPair fp : DataTypeOps.fieldList(arr)) {
                    c.add(ctx.requireDataType(fp.type), fp.name, null);
                }
            }
        } else if (dt instanceof Enum) {
            if (req.has("addEntries") && req.get("addEntries").isJsonArray()) {
                for (DataTypeOps.EnumEntry ee : DataTypeOps.enumEntries(req.getAsJsonArray("addEntries"))) {
                    ((Enum) dt).add(ee.name, ee.value);
                }
            }
        } else if (dt instanceof TypeDef) {
            if (req.has("base") && !req.get("base").isJsonNull()) {
                throw new IllegalArgumentException(
                    "Typedef 'base' change requires delete + recreate; not yet supported.");
            }
        }
    }
}
