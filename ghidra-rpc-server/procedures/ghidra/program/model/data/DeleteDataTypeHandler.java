package procedures.ghidra.program.model.data;

import java.util.Collections;

import com.google.gson.JsonObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure DeleteDataType: remove a user-defined data type by full path.
 *
 * Built-in types are rejected. The bulk {@link DataTypeManager#remove(java.util.List,
 * ghidra.util.task.TaskMonitor)} entry point is used instead of the singleton
 * {@code remove(DataType, TaskMonitor)}, which is deprecated for removal. Both
 * delegate to the same internal code, but the bulk one is not on the removal
 * list.
 *
 * On success returns {@code {success:true, path}} with the deleted path; the
 * program is checked in by the dispatcher.
 */
public final class DeleteDataTypeHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "path");
        DataType dt = DataTypeOps.requireDataTypeByPath(ctx, path);
        if (DataTypeOps.isBuiltIn(ctx, dt)) {
            return RpcResponse.error("Cannot delete built-in type '" + dt.getName() + "'.");
        }
        // remove(List, TaskMonitor) is the non-deprecated entry point and returns
        // void; we treat any exception (cancellation, conflict, in-use) as a
        // hard failure and surface it verbatim.
        ctx.runWrite("DeleteDataType", () -> {
            try {
                ctx.program().getDataTypeManager()
                    .remove(Collections.singletonList(dt), ctx.monitor());
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        });
        JsonObject o = new JsonObject();
        o.addProperty("success", true);
        o.addProperty("path", path);
        o.addProperty("deleted", true);
        return new DeleteResponse(o);
    }

    static final class DeleteResponse extends RpcResponse {
        final String path;
        final boolean deleted;
        DeleteResponse(JsonObject o) {
            this.success = true;
            this.path = o.get("path").getAsString();
            this.deleted = o.get("deleted").getAsBoolean();
        }
    }
}