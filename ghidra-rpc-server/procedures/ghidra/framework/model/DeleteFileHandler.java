package procedures.ghidra.framework.model;

import java.io.IOException;

import com.google.gson.JsonObject;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.remote.RepositoryItem;

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
 * which is why this is admin-only (see {@link #requiresAdmin()}).
 *
 * <p>Shared project: if this server's checkout was terminated by another
 * session, the local copy is a private "hijack" file shadowing the server's
 * file, and {@code DomainFile.delete()} removes only that private copy
 * (GhidraFileData.delete, hijack branch), revealing the server file. The
 * handler then deletes the revealed file as well. Afterwards the repository
 * must have no item at the path, or the request fails: "deleted" is only
 * reported when the Ghidra Server confirms it. A delete the server refuses
 * (versions owned by another user without repository admin rights, another
 * user's checkout) is an error.
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
        RepositoryAdapter repo = ctx.project().getRepository();
        try {
            // This server keeps every file it has opened or imported open and
            // checked out, and DomainFile.delete() refuses both states; without
            // this the delete could only ever succeed on untouched files.
            ctx.releaseFile(df);
            boolean hijacked = repo != null && df.isHijacked();
            df.delete();
            if (hijacked) {
                // Only the private copy is gone; the server file is visible again.
                DomainFile revealed = ctx.project().getProjectData().getFile(deletedPath);
                if (revealed != null) {
                    ctx.releaseFile(revealed);
                    revealed.delete();
                }
            }
        } catch (Exception e) {
            return RpcResponse.error("delete '" + path + "': " + e.getMessage());
        }
        if (repo != null) {
            // Post-condition: Ghidra's delete paths can succeed locally while
            // the server keeps the file (see the class comment). Trust the server.
            int slash = deletedPath.lastIndexOf('/');
            String parent = slash <= 0 ? "/" : deletedPath.substring(0, slash);
            RepositoryItem left;
            try {
                left = repo.getItem(parent, deletedPath.substring(slash + 1));
            } catch (IOException e) {
                return RpcResponse.error("delete '" + path + "': could not confirm the deletion "
                    + "with the Ghidra Server: " + e.getMessage());
            }
            if (left != null) {
                return RpcResponse.error("delete '" + path + "': the file is still in the Ghidra "
                    + "Server repository (version " + left.getVersion() + "); nothing was deleted "
                    + "there.");
            }
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
