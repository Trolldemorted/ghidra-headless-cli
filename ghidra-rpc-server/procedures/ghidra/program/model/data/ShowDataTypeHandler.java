package procedures.ghidra.program.model.data;

import com.google.gson.JsonObject;

import ghidra.program.model.data.DataType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure ShowDataType: read a single data type by full path
 * ({@code /Category/Sub/Name}) and return its full description (struct fields,
 * enum entries, typedef base, etc.). Read-only.
 */
public final class ShowDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        DataType dt = DataTypeOps.requireDataTypeByPath(ctx, RpcContext.reqStr(req, "path"));
        DataTypeSerializer ser = new DataTypeSerializer(ctx.program().getDataTypeManager());
        return new ShowResponse(ser.describe(dt));
    }

    @Override public boolean mutates() { return false; }

    static final class ShowResponse extends RpcResponse {
        final String kind;
        final String name;
        final String path;
        final String category;
        final long size;
        final String source;
        final String sourceArchive;
        final JsonObject detail;

        ShowResponse(JsonObject o) {
            this.success = true;
            this.kind = o.has("kind") ? o.get("kind").getAsString() : null;
            this.name = o.has("name") ? o.get("name").getAsString() : null;
            this.path = o.has("path") ? o.get("path").getAsString() : null;
            this.category = o.has("category") ? o.get("category").getAsString() : null;
            this.size = o.has("size") ? o.get("size").getAsLong() : 0;
            this.source = o.has("source") ? o.get("source").getAsString() : null;
            this.sourceArchive = o.has("sourceArchive") && !o.get("sourceArchive").isJsonNull()
                ? o.get("sourceArchive").getAsString() : null;
            this.detail = o;
        }
    }
}