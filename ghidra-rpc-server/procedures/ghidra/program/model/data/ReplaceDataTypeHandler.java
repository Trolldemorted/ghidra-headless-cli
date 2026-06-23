package procedures.ghidra.program.model.data;

import com.google.gson.JsonObject;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure ReplaceDataType: create or REPLACE a struct / union / enum / typedef.
 *
 * Same input shapes as {@link CreateDataType} (explicit kind+name+pieces, or a
 * {@code definition} C snippet). The difference is the conflict policy: this
 * procedure uses {@link DataTypeConflictHandler#REPLACE_HANDLER}, so a name
 * clash silently overwrites the existing type in place. References in
 * function signatures, applied data, and other types are preserved.
 *
 * <p>This is the CLI equivalent of the Ghidra GUI "Replace..." action on a
 * type in the Data Type Manager. The key use case is overwriting an
 * archive-resolved stub (a type pulled in from an upstream archive like
 * {@code Battle_Realms_F.exe}) with a user-defined version: the new
 * type lives in the program DTM under the same name and category, and
 * all references automatically resolve to the local copy.
 *
 * <p>The target can be specified two ways:
 * <ul>
 *   <li>{@code path="/Demangler/L_String"} — full path, used verbatim.
 *       This is the disambiguating form when the same name appears in
 *       multiple categories (as happens for auto-typed stubs).</li>
 *   <li>{@code name} + optional {@code category} (default {@code /}).
 *       Shorter, but ambiguous when name collisions exist.</li>
 * </ul>
 *
 * Use {@link CreateDataType} if you want a name clash to be an error.
 *
 * <p>Implementation note: type construction AND category.addDataType must
 * run inside the same transaction; the DTM refuses to add a type outside
 * an active transaction ("Transaction has not been started").
 */
public final class ReplaceDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        DataTypeManager dtm = ctx.program().getDataTypeManager();

        // Resolve the target path up-front so we can use it on both the
        // C-snippet path and the explicit-JSON path. When `path` is given,
        // it wins over `name`+`category`; conflicts_with on the CLI side
        // blocks both being set at once.
        final CategoryPath cp;
        final String name;
        String path = RpcContext.optStr(req, "path");
        if (path != null && !path.isEmpty()) {
            // Path form: split at the last `/`. "/Demangler/L_String" ->
            // CategoryPath("/Demangler"), name="L_String". Bare "/X" means
            // root category with name X; "/" alone is rejected.
            String trimmed = path;
            while (trimmed.endsWith("/") && trimmed.length() > 1) {
                trimmed = trimmed.substring(0, trimmed.length() - 1);
            }
            int slash = trimmed.lastIndexOf('/');
            if (slash < 0) {
                return RpcResponse.error("'path' must be absolute (start with '/'): '"
                    + path + "'.");
            }
            String cat = trimmed.substring(0, slash);
            name = trimmed.substring(slash + 1);
            if (name.isEmpty()) {
                return RpcResponse.error("'path' must end with a type name: '" + path + "'.");
            }
            cp = cat.isEmpty() ? CategoryPath.ROOT : new CategoryPath(cat);
        } else {
            name = RpcContext.reqStr(req, "name");
            if (name.isEmpty()) return RpcResponse.error("Missing 'name' (or 'path').");
            cp = DataTypeOps.normalizePath(RpcContext.optStr(req, "category"));
        }

        // Fast path: a C snippet. The snippet's embedded name must match
        // the resolved `name` (and the snippet's natural category must
        // match `cp`, or both be root) so the parsed type lands at the
        // target path. CParser rejects anonymous types (see CDefinitionParser).
        String defn = RpcContext.optStr(req, "definition");
        if (defn != null && !defn.isEmpty()) {
            DataType parsed;
            try {
                parsed = CDefinitionParser.parse(defn, dtm);
            } catch (IllegalArgumentException e) {
                return RpcResponse.error(e.getMessage());
            }
            // CParser puts the parsed type in the program DTM under its
            // own declared category. If that doesn't match the requested
            // `cp`, re-parent it before addDataType so the type lives at
            // the target path. (Without this, a snippet like
            // `struct L_String { ... };` with --path /MyTest/L_String
            // would silently land at /L_String, which is surprising.)
            CategoryPath parsedCp = parsed.getCategoryPath();
            if (!parsedCp.equals(cp) || !parsed.getName().equals(name)) {
                try {
                    parsed.setNameAndCategory(cp, name);
                } catch (Exception e) {
                    return RpcResponse.error(
                        "Cannot reparent parsed type to '" + cp + "/" + name + "': "
                        + e.getMessage() + ". The snippet must declare a name matching "
                        + "the path's last segment.");
                }
            }
            DataType[] result = {null};
            Throwable[] err = {null};
            ctx.runWrite("ReplaceDataType", () -> {
                try {
                    result[0] = dtm.addDataType(parsed, DataTypeConflictHandler.REPLACE_HANDLER);
                } catch (Throwable t) {
                    err[0] = t;
                }
            });
            if (err[0] != null) return RpcResponse.error(err[0].getMessage());
            if (result[0] == null) {
                return RpcResponse.error("addDataType returned null for '"
                    + parsed.getName() + "'.");
            }
            return new ShowDataTypeHandler.ConfirmResponse(dtm, result[0], "replaced");
        }

        // Explicit-JSON path. Build the type piece-by-piece and add it.
        String kind = RpcContext.reqStr(req, "kind").toLowerCase();
        // Auto-create the parent category if it doesn't exist. Both
        // createCategory AND addDataType require an active transaction,
        // so the category lookup and creation both happen inside runWrite.
        // createCategory is idempotent — if the category already exists,
        // it just returns the existing one.
        DataType[] result = {null};
        Throwable[] err = {null};
        ctx.runWrite("ReplaceDataType", () -> {
            try {
                Category category = dtm.getCategory(cp);
                if (category == null) {
                    category = dtm.createCategory(cp);
                }
                DataType dt;
                switch (kind) {
                    case "struct":  dt = createStruct(req, name, cp, dtm, ctx); break;
                    case "union":   dt = createUnion(req, name, cp, dtm, ctx); break;
                    case "enum":    dt = createEnum(req, name, cp); break;
                    case "typedef": dt = createTypedef(req, name, cp, dtm, ctx); break;
                    default: throw new IllegalArgumentException("Unknown kind '" + kind
                        + "' (use struct|union|enum|typedef).");
                }
                result[0] = category.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
            } catch (Throwable t) {
                err[0] = t;
            }
        });
        if (err[0] != null) return RpcResponse.error(err[0].getMessage());
        if (result[0] == null) {
            return RpcResponse.error("addDataType returned null for '" + name + "'.");
        }
        return new ShowDataTypeHandler.ConfirmResponse(dtm, result[0], "replaced");
    }

    private DataType createStruct(JsonObject req, String name, CategoryPath cp,
            DataTypeManager dtm, RpcContext ctx) throws Exception {
        int size = RpcContext.optInt(req, "size", 0);
        StructureDataType s = new StructureDataType(cp, name, size, dtm);
        if (req.has("fields") && req.get("fields").isJsonArray()) {
            for (DataTypeOps.FieldPair fp : DataTypeOps.fieldList(req.getAsJsonArray("fields"))) {
                s.add(ctx.requireDataType(fp.type), fp.name, null);
            }
        }
        return s;
    }

    private DataType createUnion(JsonObject req, String name, CategoryPath cp,
            DataTypeManager dtm, RpcContext ctx) throws Exception {
        UnionDataType u = new UnionDataType(cp, name, dtm);
        if (req.has("fields") && req.get("fields").isJsonArray()) {
            for (DataTypeOps.FieldPair fp : DataTypeOps.fieldList(req.getAsJsonArray("fields"))) {
                u.add(ctx.requireDataType(fp.type), fp.name, null);
            }
        }
        return u;
    }

    private DataType createEnum(JsonObject req, String name, CategoryPath cp) throws Exception {
        int size = RpcContext.optInt(req, "enumSize", 0);
        if (size <= 0) size = RpcContext.optInt(req, "size", 4);
        EnumDataType e = new EnumDataType(cp, name, size);
        if (req.has("entries") && req.get("entries").isJsonArray()) {
            for (DataTypeOps.EnumEntry ee : DataTypeOps.enumEntries(req.getAsJsonArray("entries"))) {
                e.add(ee.name, ee.value);
            }
        }
        return e;
    }

    private DataType createTypedef(JsonObject req, String name, CategoryPath cp,
            DataTypeManager dtm, RpcContext ctx) throws Exception {
        return new TypedefDataType(cp, name,
            ctx.requireDataType(RpcContext.reqStr(req, "base")), dtm);
    }
}
