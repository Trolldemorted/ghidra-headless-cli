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
 * Procedure CreateDataType: create a new struct / union / enum / typedef.
 *
 * Program-level and mutating. {@code kind} selects the flavour:
 *   - struct: {@code fields} (array of {name, type}). The struct grows with
 *     fields; alignment/packing is Ghidra-default (no API hook to override it
 *     on creation — use {@code EditDataType} for post-create tweaks).
 *   - union: {@code fields} only.
 *   - enum: {@code entries} (array of {name, value}), {@code enumSize} (default 4).
 *   - typedef: {@code base} (C-syntax type).
 *
 * Field {@code type} and typedef {@code base} are parsed via
 * {@link RpcContext#requireDataType} against the program's DTM.
 *
 * Conflict policy: {@link DataTypeConflictHandler#DEFAULT_HANDLER} — on a name
 * clash in the target category, the call returns {@code success:false} without
 * modifying state.
 *
 * Implementation note: type construction AND category.addDataType must run
 * inside the same transaction; the DTM refuses to add a type outside an
 * active transaction ("Transaction has not been started"). The construction
 * uses the live DTM, which the in-flight transaction provides.
 */
public final class CreateDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String kind = RpcContext.reqStr(req, "kind").toLowerCase();
        String name = RpcContext.reqStr(req, "name");
        if (name.isEmpty()) {
            return RpcResponse.error("Missing 'name'.");
        }
        CategoryPath cp = DataTypeOps.normalizePath(RpcContext.optStr(req, "category"));

        DataTypeManager dtm = ctx.program().getDataTypeManager();
        Category category = dtm.getCategory(cp);
        if (category == null) {
            return RpcResponse.error("No data-type category for '" + cp + "'.");
        }

        Object[] result = {null}; // {DataType added}
        Throwable[] err = {null};
        ctx.runWrite("CreateDataType", () -> {
            try {
                DataType dt;
                switch (kind) {
                    case "struct":  dt = createStruct(req, name, cp, dtm, ctx); break;
                    case "union":   dt = createUnion(req, name, cp, dtm, ctx); break;
                    case "enum":    dt = createEnum(req, name, cp); break;
                    case "typedef": dt = createTypedef(req, name, cp, dtm, ctx); break;
                    default:
                        throw new IllegalArgumentException("Unknown kind '" + kind
                            + "' (use struct|union|enum|typedef).");
                }
                result[0] = category.addDataType(dt, new StrictConflictHandler());
            } catch (Throwable t) {
                err[0] = t;
            }
        });

        if (err[0] != null) {
            String m = err[0].getMessage();
            return RpcResponse.error(m != null ? m
                : "Data-type conflict for '" + name + "' in '" + cp + "'.");
        }
        DataType added = (DataType) result[0];
        if (added == null) {
            return RpcResponse.error("Data-type '" + name + "' already exists in '" + cp + "'.");
        }
        DataTypeSerializer ser = new DataTypeSerializer(ctx.program().getDataTypeManager());
        return new ShowDataTypeHandler.ShowResponse(ser.describe(added));
    }

    private DataType createStruct(JsonObject req, String name, CategoryPath cp,
            DataTypeManager dtm, RpcContext ctx) throws Exception {
        // size=0 → packed/growing struct (Ghidra picks this from the constructor)
        int size = RpcContext.optInt(req, "size", 0);
        StructureDataType s = new StructureDataType(cp, name, size, dtm);
        if (req.has("fields") && req.get("fields").isJsonArray()) {
            for (DataTypeOps.FieldPair fp : DataTypeOps.fieldList(req.getAsJsonArray("fields"))) {
                DataType fdt = ctx.requireDataType(fp.type);
                s.add(fdt, fp.name, null);
            }
        }
        return s;
    }

    private DataType createUnion(JsonObject req, String name, CategoryPath cp,
            DataTypeManager dtm, RpcContext ctx) throws Exception {
        UnionDataType u = new UnionDataType(cp, name, dtm);
        if (req.has("fields") && req.get("fields").isJsonArray()) {
            for (DataTypeOps.FieldPair fp : DataTypeOps.fieldList(req.getAsJsonArray("fields"))) {
                DataType fdt = ctx.requireDataType(fp.type);
                u.add(fdt, fp.name, null);
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
        String baseText = RpcContext.reqStr(req, "base");
        DataType base = ctx.requireDataType(baseText);
        return new TypedefDataType(cp, name, base, dtm);
    }
}
