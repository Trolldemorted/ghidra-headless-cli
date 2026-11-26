package procedures.ghidra.framework.model;

import com.google.gson.JsonObject;

import ghidra.framework.model.DomainFile;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure DeleteFile: remove a file (or empty folder) from the project tree.
 *
 * <p>Request: {@code { file: "<project path>" }}. Path is strict (exact match
 * only, mirroring {@link RpcContext#requireDomainFile}). Refuses to delete the
 * root folder.
 *
 * <p>If this server has the file open or checked out, its cached Program is
 * released and its own checkout undone first (Ghidra refuses to delete a file
 * in either state). A checkout held by ANOTHER client still blocks the delete.
 * On a version-controlled repository the file and all its versions are removed,
 * which is why this is admin-only (see {@link #requiresAdmin()}): it is the
 * same outcome as {@code PurgeVersions} with {@code keep = 0}.
 *
 * <p>Project-level ({@link #needsProgram()} = false): no {@code file} field
 * is required from the dispatcher (the path is consumed as the delete target,
 * not as a program open). The dispatch lock is still held across the whole
 * operation, so a delete cannot race against an open-and-edit of the same file.
 * Dispatcher check-in is skipped because no program was opened.
 */
public final class DeleteFileHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "file");
        // requireDomainFile only resolves to DomainFile; folders are DomainFolder
        // (separate type) so passing a folder path naturally fails with
        // "No file at PATH" — no extra guard needed.
        DomainFile df = ctx.requireDomainFile(path);
        String name = df.getName();
        String deletedPath = df.getPathname();
        try {
            // This server keeps every file it has opened or imported open and
            // checked out, and DomainFile.delete() refuses both states; without
            // this the delete could only ever succeed on untouched files.
            ctx.releaseFile(df);
            df.delete();
        } catch (Exception e) {
            return RpcResponse.error("delete '" + path + "': " + e.getMessage());
        }
        return new DeleteFileResponse(name, deletedPath);
    }

    @Override
    public boolean needsProgram() {
        return false; // operates on the project tree, not a program
    }

    @Override
    public boolean mutates() {
        return true; // dispatcher check-in is gated on a non-null program, so this is safe
    }

    @Override
    public boolean requiresAdmin() {
        return true; // gated by GHIDRA_RPC_ADMIN_PASSWORD, like PurgeVersions
    }

    /** Minimal confirmation. The CLI prints one line: "deleted <name> (was <path>)". */
    static final class DeleteFileResponse extends RpcResponse {
        @SuppressWarnings("unused")
        final String name;
        @SuppressWarnings("unused")
        final String path;

        DeleteFileResponse(String name, String path) {
            this.success = true;
            this.name = name;
            this.path = path;
        }
    }
}
