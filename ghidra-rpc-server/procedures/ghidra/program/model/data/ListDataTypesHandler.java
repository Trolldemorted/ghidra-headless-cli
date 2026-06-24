package procedures.ghidra.program.model.data;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure ListDataTypes: enumerate data types under a category.
 *
 * Program-level read-only. {@code folder} (default "/") scopes the walk;
 * {@code recursive} (default true) descends into subcategories; {@code kind}
 * (default "all") keeps only types of that kind (struct/union/enum/typedef);
 * {@code limit} caps the result and sets {@code truncated}. Entries are sorted
 * by path.
 */
public final class ListDataTypesHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        CategoryPath folderPath = DataTypeOps.normalizePath(RpcContext.optStr(req, "category"));
        boolean recursive = RpcContext.reqBool(req, "recursive");
        String kind = RpcContext.optStr(req, "kind");
        int limit = RpcContext.reqInt(req, "limit");

        Category root = ctx.program().getDataTypeManager().getCategory(folderPath);
        if (root == null) {
            return RpcResponse.error("No data-type category for '" + folderPath + "'.");
        }

        DataTypeSerializer ser = new DataTypeSerializer(ctx.program().getDataTypeManager());
        List<JsonObject> out = new ArrayList<>();
        collect(root, recursive, kind, ser, out, ctx);

        out.sort(Comparator.comparing(o -> o.get("path").getAsString()));
        boolean truncated = false;
        if (limit > 0 && out.size() > limit) {
            out = new ArrayList<>(out.subList(0, limit));
            truncated = true;
        }

        JsonArray arr = new JsonArray();
        for (JsonObject o : out) arr.add(o);
        JsonObject response = new JsonObject();
        response.addProperty("success", true);
        response.addProperty("count", out.size());
        response.addProperty("truncated", truncated);
        response.add("types", arr);
        return new ListResponse(response);
    }

    private void collect(Category cat, boolean recursive, String kindFilter,
            DataTypeSerializer ser, List<JsonObject> out, RpcContext ctx) throws Exception {
        for (DataType dt : cat.getDataTypes()) {
            ctx.monitor().checkCancelled();
            if (kindFilter != null && !kindFilter.isEmpty()
                    && !kindFilter.equalsIgnoreCase("all")) {
                String k = DataTypeSerializer.kindOf(dt);
                if (!kindFilter.equalsIgnoreCase(k)) {
                    continue;
                }
            }
            out.add(ser.summarize(dt));
        }
        if (recursive) {
            for (Category sub : cat.getCategories()) {
                ctx.monitor().checkCancelled();
                collect(sub, recursive, kindFilter, ser, out, ctx);
            }
        }
    }

    @Override public boolean mutates() { return false; }

    static final class ListResponse extends RpcResponse {
        final int count;
        final boolean truncated;
        final JsonArray types;
        ListResponse(JsonObject o) {
            this.success = true;
            this.count = o.get("count").getAsInt();
            this.truncated = o.get("truncated").getAsBoolean();
            this.types = o.getAsJsonArray("types");
        }
    }
}