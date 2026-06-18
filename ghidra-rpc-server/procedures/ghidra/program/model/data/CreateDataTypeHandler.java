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
 * Procedure CreateDataType: create a struct / union / enum / typedef.
 *
 * Two input shapes (either wins; {@code definition} wins when both given):
 *   1. explicit {@code kind} + {@code name} + (fields|entries|base)
 *   2. {@code definition}: a C snippet parsed by {@link CDefinitionParser}
 *
 * <p><b>Fail on name collision.</b> If a type with the same name already
 * exists in the target category, the call returns
 * {@code success:false} with the error
 * {@code Data type 'X' already exists in /category.}. Use
 * {@code ReplaceDataType} to overwrite an existing type in place.
 *
 * <p>Implementation note: type construction AND category.addDataType must
 * run inside the same transaction; the DTM refuses to add a type outside
 * an active transaction ("Transaction has not been started").
 */
public final class CreateDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        DataTypeManager dtm = ctx.program().getDataTypeManager();

        // C-snippet path. Parse, then pre-check the parsed name.
        String defn = RpcContext.optStr(req, "definition");
        if (defn != null && !defn.isEmpty()) {
            DataType parsed;
            try {
                parsed = CDefinitionParser.parse(defn, dtm);
            } catch (IllegalArgumentException e) {
                return RpcResponse.error(e.getMessage());
            }
            CategoryPath cp = parsed.getCategoryPath();
            DataType existing = dtm.getDataType(cp, parsed.getName());
            if (existing != null) {
                return RpcResponse.error("Data type '" + parsed.getName()
                    + "' already exists in " + cp + ".");
            }
            DataType[] result = {null};
            Throwable[] err = {null};
            ctx.runWrite("CreateDataType", () -> {
                try {
                    result[0] = dtm.addDataType(parsed, DataTypeConflictHandler.DEFAULT_HANDLER);
                } catch (Throwable t) {
                    err[0] = t;
                }
            });
            if (err[0] != null) return RpcResponse.error(err[0].getMessage());
            if (result[0] == null) {
                return RpcResponse.error("addDataType returned null for '"
                    + parsed.getName() + "'.");
            }
            return new ShowDataTypeHandler.ShowResponse(
                new DataTypeSerializer(dtm).describe(result[0]));
        }

        // Explicit-JSON path. Build the type, pre-check the name, add.
        String kind = RpcContext.reqStr(req, "kind").toLowerCase();
        String name = RpcContext.reqStr(req, "name");
        if (name.isEmpty()) return RpcResponse.error("Missing 'name'.");
        final CategoryPath cp = DataTypeOps.normalizePath(RpcContext.optStr(req, "category"));
        Category category = dtm.getCategory(cp);
        if (category == null) return RpcResponse.error("No data-type category for '" + cp + "'.");
        if (dtm.getDataType(cp, name) != null) {
            return RpcResponse.error("Data type '" + name
                + "' already exists in " + cp + ".");
        }

        DataType[] result = {null};
        Throwable[] err = {null};
        ctx.runWrite("CreateDataType", () -> {
            try {
                DataType dt;
                switch (kind) {
                    case "struct":  dt = createStruct(req, name, cp, dtm, ctx); break;
                    case "union":   dt = createUnion(req, name, cp, dtm, ctx); break;
                    case "enum":    dt = createEnum(req, name, cp); break;
                    case "typedef": dt = createTypedef(req, name, cp, dtm, ctx); break;
                    default: throw new IllegalArgumentException("Unknown kind '" + kind
                        + "' (use struct|union|enum|typedef).");
                }
                result[0] = category.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
            } catch (Throwable t) {
                err[0] = t;
            }
        });
        if (err[0] != null) return RpcResponse.error(err[0].getMessage());
        if (result[0] == null) {
            return RpcResponse.error("addDataType returned null for '" + name + "'.");
        }
        return new ShowDataTypeHandler.ShowResponse(
            new DataTypeSerializer(dtm).describe(result[0]));
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
