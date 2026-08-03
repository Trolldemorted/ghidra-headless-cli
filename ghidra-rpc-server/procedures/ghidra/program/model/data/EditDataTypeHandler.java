package procedures.ghidra.program.model.data;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
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
            return new ShowDataTypeHandler.ConfirmResponse(
                ctx.program().getDataTypeManager(), target, "edited");
        }

        // Explicit-JSON path: rename / move / replaceFields / addFields / addEntries.
        boolean[] touched = {false};
        ctx.runWrite("EditDataType", () -> {
            doEdits(req, target, ctx);
            touched[0] = true;
        });
        if (!touched[0]) return RpcResponse.error("Edit failed for '" + target.getName() + "'.");
        return new ShowDataTypeHandler.ConfirmResponse(
            ctx.program().getDataTypeManager(), target, "edited");
    }

    private static boolean sameKind(DataType a, DataType b) {
        if (a instanceof Composite) return b instanceof Composite;
        if (a instanceof Enum) return b instanceof Enum;
        if (a instanceof TypeDef) return b instanceof TypeDef;
        if (a instanceof FunctionDefinition) return b instanceof FunctionDefinition;
        return a.getClass().equals(b.getClass());
    }

    private static String kindName(DataType dt) {
        if (dt instanceof Composite) {
            return dt instanceof ghidra.program.model.data.Union ? "union" : "struct";
        }
        if (dt instanceof Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof FunctionDefinition) return "functiondef";
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
        if (req.has("description") && !req.get("description").isJsonNull()) {
            String desc = req.get("description").getAsString();
            // TypedefDataType in Ghidra 12.x does NOT override
            // setDescription; the inherited default is a silent no-op
            // (verified via javap + end-to-end test on Ghidra 12.1.2).
            // That would make the call "succeed" without persisting the
            // description, which is worse than a thrown exception — the
            // user would not know their annotation was lost. Detect
            // typedefs up front and surface a clear error pointing at the
            // underlying type.
            if (dt instanceof TypeDef) {
                throw new IllegalArgumentException(
                    "Cannot set description on typedef '/" + dt.getName()
                    + "' — Ghidra's TypedefDataType does not persist per-typedef descriptions. "
                    + "Set the description on the underlying type instead "
                    + "(use `datatype show --path /X` to discover the path).");
            }
            try {
                dt.setDescription(desc);
            } catch (UnsupportedOperationException e) {
                // Defensive: any future Ghidra version that DOES throw
                // here will still get a clear error rather than a 500.
                throw new IllegalArgumentException(
                    "Cannot set description on '/" + dt.getName()
                    + "': " + e.getMessage()
                    + ". Set the description on the underlying type instead.");
            }
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
        } else if (dt instanceof FunctionDefinition) {
            applyFunctionDefinitionEdits(req, (FunctionDefinition) dt, ctx);
        }
    }

    /**
     * Mutate a {@link FunctionDefinition} in place. Every field is
     * presence-sensitive: omitting a key leaves the corresponding state
     * untouched. Use {@code parameters: []} (empty array, key present) to
     * CLEAR the argument list — distinct from omitting the key.
     *
     * <p>All setters run inside the dispatcher-owned transaction (the
     * {@code runWrite} wrapper at the top of {@link #execute}), so any
     * throw — including {@link ghidra.util.exception.InvalidInputException}
     * from {@code setCallingConvention} for a name the program's
     * {@code CompilerSpec} doesn't recognize — rolls back every prior
     * setter in the same request. Callers see {@code success:false} with
     * the underlying Ghidra message.
     *
     * <p>The C {@code definition} snippet path at the top of
     * {@link #execute} does NOT route through this branch: funcdef snippets
     * would need a separate parser path that bypasses
     * {@link RpcContext#parseSignature}'s convention-keyword rejection
     * (see memory
     * {@code apply_signature_convention_keyword_fix.md}). Deferred.
     */
    private void applyFunctionDefinitionEdits(JsonObject req,
            FunctionDefinition fd, RpcContext ctx) throws Exception {
        if (req.has("returnType") && !req.get("returnType").isJsonNull()) {
            fd.setReturnType(ctx.requireDataType(
                RpcContext.reqStr(req, "returnType")));
        }
        if (req.has("parameters") && !req.get("parameters").isJsonNull()) {
            JsonElement pel = req.get("parameters");
            if (!pel.isJsonArray()) {
                throw new IllegalArgumentException(
                    "'parameters' must be a JSON array of {name, type} objects.");
            }
            List<ParameterDefinition> params = new ArrayList<>();
            for (JsonElement element : pel.getAsJsonArray()) {
                if (!element.isJsonObject()) {
                    throw new IllegalArgumentException(
                        "Each parameter must be a {name, type} object.");
                }
                JsonObject p = element.getAsJsonObject();
                String name = (p.has("name") && !p.get("name").isJsonNull())
                    ? p.get("name").getAsString()
                    : "";
                String type = RpcContext.reqStr(p, "type");
                params.add(new ParameterDefinitionImpl(
                    name, ctx.requireDataType(type), null));
            }
            // Empty array clears the argument list. Distinct from "field
            // omitted" because the key is present and an empty list.
            fd.setArguments(params.toArray(new ParameterDefinition[0]));
        }
        if (req.has("callingConvention")
                && !req.get("callingConvention").isJsonNull()) {
            fd.setCallingConvention(RpcContext.reqStr(req, "callingConvention"));
        }
        if (req.has("varArgs") && !req.get("varArgs").isJsonNull()) {
            fd.setVarArgs(req.get("varArgs").getAsBoolean());
        }
        if (req.has("noReturn") && !req.get("noReturn").isJsonNull()) {
            fd.setNoReturn(req.get("noReturn").getAsBoolean());
        }
    }
}
