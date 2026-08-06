package procedures.ghidra.program.model.data;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
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
            Category category = dtm.getCategory(cp);
            if (category == null) {
                return RpcResponse.error("No data-type category for '" + cp + "'.");
            }
            // Category.getDataType(name) sees archive-resolved stubs too —
            // DataTypeManager.getDataType(cp, name) only sees the program DTM
            // and misses auto-typed defaults pulled in from upstream archives,
            // allowing silent duplicates when the user-defined name collides
            // with an archive-resolved type of the same name.
            DataType existing = category.getDataType(parsed.getName());
            if (existing != null) {
                return RpcResponse.error(collisionMessage(parsed.getName(), cp, existing));
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
            return new ShowDataTypeHandler.ConfirmResponse(dtm, result[0], "created");
        }

        // Explicit-JSON path. Build the type, pre-check the name, add.
        String kind = RpcContext.reqStr(req, "kind").toLowerCase();
        String name = RpcContext.reqStr(req, "name");
        if (name.isEmpty()) return RpcResponse.error("Missing 'name'.");
        final CategoryPath cp = DataTypeOps.normalizePath(RpcContext.optStr(req, "category"));
        Category category = dtm.getCategory(cp);
        if (category == null) return RpcResponse.error("No data-type category for '" + cp + "'.");
        // See note above: Category.getDataType(name) sees archive-resolved
        // stubs (auto-typed defaults pulled in from upstream archives),
        // DataTypeManager.getDataType(cp, name) does not.
        DataType existing = category.getDataType(name);
        if (existing != null) {
            return RpcResponse.error(collisionMessage(name, cp, existing));
        }

        DataType[] result = {null};
        Throwable[] err = {null};
        ctx.runWrite("CreateDataType", () -> {
            try {
                DataType dt;
                switch (kind) {
                    case "struct":
                        dt = createStruct(req, name, cp, dtm, ctx);
                        break;
                    case "union":
                        dt = createUnion(req, name, cp, dtm, ctx);
                        break;
                    case "enum":
                        dt = createEnum(req, name, cp);
                        break;
                    case "typedef":
                        dt = createTypedef(req, name, cp, dtm, ctx);
                        break;
                    case "funcdef":
                        dt = createFuncdef(req, name, cp, dtm, ctx);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown kind '" + kind
                            + "' (use struct|union|enum|typedef|funcdef).");
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
        return new ShowDataTypeHandler.ConfirmResponse(dtm, result[0], "created");
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
        int size = RpcContext.reqInt(req, "enumSize");
        if (size <= 0) size = 4; // defensive: caller passed 0 or negative
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

    /**
     * Build a {@link FunctionDefinitionDataType} from the explicit-JSON
     * args. Mirrors {@code EditDataTypeHandler.applyFunctionDefinitionEdits}
     * (which already handles the edit-in-place case) so the wire shape is
     * identical between create and edit: callers can copy a payload between
     * the two procedures without reshaping.
     *
     * <p>Behavior on the {@code __thiscall} leading {@code this}: the user
     * passes it as the first parameter in the {@code parameters} array —
     * this helper does NOT auto-inject it (compare with
     * {@code CreateFunctionDefinitionFromSourceCmd}, which does inject the
     * auto-this from the source function's parameter list). Reason: a
     * from-scratch funcdef has no source function to read from; the
     * convention alone doesn't determine whether the user wants the
     * implicit ECX slot. The convention is preserved via
     * {@code setCallingConvention} (which accepts {@code "__thiscall"} and
     * every other name the program's {@code CompilerSpec} recognizes), and
     * the leading parameter, if any, is whatever the caller put there.
     *
     * <p>Fail-loud on unknown parameter types: {@code requireDataType} throws
     * {@code IllegalArgumentException} when the type does not exist; the
     * enclosing {@code runWrite} block propagates the throw, the
     * transaction rolls back, and the caller sees the Ghidra-side message.
     * No silent {@code undefined4} substitution.
     */
    private DataType createFuncdef(JsonObject req, String name, CategoryPath cp,
            DataTypeManager dtm, RpcContext ctx) throws Exception {
        FunctionDefinitionDataType fd = new FunctionDefinitionDataType(cp, name, dtm);
        // returnType: required (server side; CLI forwards whatever edit accepts).
        // Omitting returnType would leave the def as void-returning (Ghidra
        // default), which is rarely what the caller wants. Make it required
        // here for the same reason "fields" is required for struct: the
        // funcdef is useless without a body.
        fd.setReturnType(ctx.requireDataType(RpcContext.reqStr(req, "returnType")));
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
                String pname = (p.has("name") && !p.get("name").isJsonNull())
                    ? p.get("name").getAsString()
                    : "";
                String ptype = RpcContext.reqStr(p, "type");
                params.add(new ParameterDefinitionImpl(
                    pname, ctx.requireDataType(ptype), null));
            }
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
        return fd;
    }

    /**
     * Render a clear "name already in use" message that tells the user what
     * they're colliding with (size, kind, source/archive) so they can decide
     * whether to use {@code ReplaceDataType}, pick a different name, or
     * inline the layout. {@code source} comes from
     * {@link DataType#getSourceArchive()} — non-null means the existing type
     * is an archive-resolved stub (the silent-duplicate case this guard was
     * added for); null means a user-defined type already lives in the program
     * DTM, which the previous (incomplete) check also caught.
     */
    private static String collisionMessage(String name, CategoryPath cp, DataType existing) {
        StringBuilder sb = new StringBuilder();
        sb.append("Data type '").append(name).append("' already exists in ")
          .append(cp).append(" (kind=").append(DataTypeSerializer.kindOf(existing))
          .append(", size=").append(existing.getLength());
        ghidra.program.model.data.SourceArchive archive = existing.getSourceArchive();
        if (archive != null) {
            sb.append(", source=archive:").append(archive.getName())
              .append(" — use 'replace' to overwrite or pick a different name");
        } else {
            sb.append(", source=program — use 'replace' to overwrite");
        }
        sb.append(").");
        return sb.toString();
    }
}
