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
        // For archive-resolved types we let Ghidra decide: if the type lives
        // in a real upstream archive (BuiltInTypes, Mapeditor.exe, ...),
        // dtm.remove() will either no-op or throw — and we surface that as
        // a clear error pointing at `datatype replace` as the right verb.
        // We do NOT pre-check isLocalProgramType() because a freshly
        // replaced type lives in the archive's domain (GUI Replace puts
        // the new entry in the archive's local copy) and should still be
        // deletable; only true upstream stubs are immutable.
        final String errorRef = errorRefFor(ctx, dt, path);

        // Find program-DTM types that depend on `dt` BEFORE the delete —
        // once `dt` is gone its dependents will show `-BAD-` placeholders
        // until each referrer is re-resolved (via `datatype replace` of
        // the referrer, or delete+create of the referrer). The walk is
        // read-only and we run it outside runWrite so the transaction
        // stays small.
        java.util.List<String> referrers = DataTypeOps.findReferrers(
            ctx.program().getDataTypeManager(), dt);

        ctx.runWrite("DeleteDataType", () -> {
            try {
                ctx.program().getDataTypeManager()
                    .remove(Collections.singletonList(dt), ctx.monitor());
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        });
        // Post-check: if the type is still there (Ghidra silently no-op'd),
        // the deletion didn't happen. This catches the "archive stub is
        // immutable" case that the GUI handles by disabling the menu item.
        DataType stillThere = null;
        try {
            stillThere = DataTypeOps.requireDataTypeByPath(ctx, path);
        } catch (IllegalArgumentException ignored) {
            // Expected: the type is gone.
        }
        if (stillThere != null) {
            return RpcResponse.error(errorRef);
        }
        JsonObject o = new JsonObject();
        o.addProperty("success", true);
        o.addProperty("path", path);
        o.addProperty("deleted", true);
        // Surface the list of referrers so the caller knows which composites
        // now have `-BAD-` placeholders. Empty array when nothing depends on
        // the deleted type — common for leaf types that no struct/union
        // references.
        com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
        for (String r : referrers) arr.add(r);
        o.add("referrers", arr);
        return new DeleteResponse(o, referrers);
    }

    /**
     * Build the "use replace instead" error message for a type Ghidra
     * refused to delete. Tells the user exactly which archive the type
     * came from, so they know what's blocking the delete.
     */
    private static String errorRefFor(RpcContext ctx, DataType dt, String path) {
        return "Cannot delete '" + dt.getName() + "' at '" + path
            + "' (source archive: " + DataTypeOps.archiveName(dt) + "). "
            + "Archive-resolved types are immutable; use `datatype replace` to "
            + "shadow the entry with a user-defined version under the same name.";
    }

    static final class DeleteResponse extends RpcResponse {
        final String path;
        final boolean deleted;
        // List of program-DTM types that referenced the deleted type and now
        // hold `-BAD-` placeholders in their field lists. Empty when nothing
        // depended on the deleted type (leaf types). Serialized by gson as
        // a JSON array on the response; CLI prints the list on stderr.
        final java.util.List<String> referrers;
        DeleteResponse(JsonObject o, java.util.List<String> referrers) {
            this.success = true;
            this.path = o.get("path").getAsString();
            this.deleted = o.get("deleted").getAsBoolean();
            this.referrers = referrers == null ? java.util.Collections.emptyList() : referrers;
        }
    }
}