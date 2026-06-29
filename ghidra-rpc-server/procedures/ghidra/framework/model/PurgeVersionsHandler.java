package procedures.ghidra.framework.model;

import java.io.IOException;

import com.google.gson.JsonObject;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.remote.User;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure PurgeVersions: delete old revisions of a single file on the
 * remote Ghidra Server, keeping the most recent {@code keep} versions.
 *
 * <p>Request: {@code { file: "<project path>", keep: <int> }}. Both fields
 * are mandatory; the server does NOT default {@code keep} (per policy "default
 * values defined in the client; server requires explicit values") so a missing
 * {@code keep} becomes a clear error. Caller must additionally carry an
 * {@code adminPassword} field matching the server's {@code RPC_ADMIN_PASSWORD}
 * — see {@link #requiresAdmin()}.
 *
 * <p>Implementation: Ghidra's {@link RepositoryAdapter#deleteItem} accepts only
 * the oldest or latest version per call (see {@code
 * LocalFolderItem.delete:301-339} — middle versions cannot be skipped). To
 * trim a contiguous prefix of old revisions we loop {@code deleteItem(folder,
 * name, oldest)} until {@code getVersions(...).length <= keep}. Version
 * numbers shift after each delete, so {@code getVersions} is re-fetched inside
 * the loop.
 *
 * <p>Per-iteration guard: if any client has a checkout on the current oldest
 * version (mirrors {@code VersionHistoryPanel.delete()}), the loop aborts with
 * a descriptive error rather than failing deep inside the server.
 *
 * <p>Admin note: the RPC server's {@code RPC_ADMIN_PASSWORD} gate is one
 * layer; the Ghidra Server's per-version ownership check (admin can delete
 * anyone's versions; non-admin only their own — {@code RepositoryFile.delete:
 * 257-281}) is another. Non-admin callers that hit the ownership rule see the
 * server's IOException surfaced verbatim plus a hint that they're not admin.
 *
 * <p>Project-level ({@link #needsProgram()} = false): no {@code file} open,
 * no checkout, no dispatcher transaction. The {@code mutates()} flag stays
 * true because the operation does mutate repository state; the dispatcher's
 * check-in is a no-op when no program is open so this is safe. The
 * admin-gate fires from the dispatcher BEFORE we touch the repository.
 */
public final class PurgeVersionsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String path = RpcContext.reqStr(req, "file");
        int keep = RpcContext.reqInt(req, "keep");
        if (keep < 0) {
            return RpcResponse.error("'keep' must be >= 0 (got " + keep + ").");
        }

        DomainFile df = ctx.requireDomainFile(path);
        // We do NOT short-circuit on df.isVersioned(): that flag flips to
        // false as soon as any single version has been removed from a
        // file (DomainFile.isVersioned() reports whether the file's
        // versioned-folder-item is active, not whether history exists).
        // The repository's getVersions() is the source of truth — if it
        // returns <= keep entries, the loop body is a no-op anyway.

        RepositoryAdapter repo = ctx.project().getRepository();
        if (repo == null) {
            return RpcResponse.error(
                "project is not connected to a Ghidra Server repository; cannot purge versions.");
        }

        // Parent folder is everything up to the last '/'; itemName is the leaf.
        // Examples: "/foo.exe" -> ("/", "foo.exe"); "/sub/bar.exe" -> ("/sub", "bar.exe").
        String fullPath = df.getPathname();
        int slash = fullPath.lastIndexOf('/');
        String parentPath = (slash <= 0) ? "/" : fullPath.substring(0, slash);
        String itemName = fullPath.substring(slash + 1);

        Version[] before;
        try {
            before = repo.getVersions(parentPath, itemName);
        } catch (IOException e) {
            return RpcResponse.error("getVersions('" + parentPath + "', '" + itemName + "'): "
                + e.getMessage());
        }
        if (before.length == 0) {
            return RpcResponse.error("'" + path + "' has no versions on the server; "
                + "(local metadata says versioned but repository disagrees).");
        }

        // Snapshot the calling user once: non-admins can only delete versions
        // they own, enforced server-side in RepositoryFile.delete:257-281. We
        // surface this hint only when a delete actually fails the check.
        User me;
        try {
            me = repo.getUser();
        } catch (IOException e) {
            me = null;
        }
        boolean isAdmin = (me != null) && me.isAdmin();

        int deleted = 0;
        int oldestDeleted = -1;
        int latestDeleted = -1;
        // "lastVersionDeleted" reports whether the loop's final deleteItem
        // call removed the last remaining version (i.e., the user requested
        // keep=0 and the call succeeded). In that case Ghidra's
        // LocalFolderItem.delete takes the minVersion==currentVersion branch
        // and calls deleteContent(), which removes the file from the
        // filesystem. The flag is informational — the repository's getVersions
        // afterward is the canonical truth (it throws FileNotFoundException
        // when the file is fully gone; an unversioned single-version file
        // returns an empty Version[]).
        boolean lastVersionDeleted = false;
        while (true) {
            Version[] current = repo.getVersions(parentPath, itemName);
            if (current.length <= keep) {
                break;
            }
            Version oldest = current[0];
            int targetVersion = oldest.getVersion();

            // Mirror the GUI guard (VersionHistoryPanel.delete): refuse if any
            // client has the target version checked out. Re-checked each
            // iteration because checkouts can appear mid-loop.
            ItemCheckoutStatus[] cos = repo.getCheckouts(parentPath, itemName);
            boolean blocked = false;
            for (ItemCheckoutStatus co : cos) {
                if (co.getCheckoutVersion() == targetVersion) {
                    blocked = true;
                    break;
                }
            }
            if (blocked) {
                return RpcResponse.error(
                    "cannot delete version " + targetVersion + " of '" + path
                    + "': one or more clients hold a checkout on it.");
            }

            try {
                repo.deleteItem(parentPath, itemName, targetVersion);
            } catch (IOException e) {
                return RpcResponse.error(
                    "deleteItem('" + parentPath + "', '" + itemName + "', " + targetVersion
                    + "): " + e.getMessage()
                    + (isAdmin ? ""
                        : " (caller is not a repo admin; can only delete versions they own)"));
            }
            deleted++;
            if (oldestDeleted < 0) {
                oldestDeleted = targetVersion;
            }
            latestDeleted = targetVersion;
            if (current.length - 1 == 0) {
                // Last version removed; the next loop iteration's getVersions
                // would either throw (file fully gone) or return [] (file
                // demoted to a single unversioned version — also acceptable
                // since the user asked for keep=0). Break out either way.
                lastVersionDeleted = true;
                break;
            }
        }

        Version[] after;
        try {
            after = repo.getVersions(parentPath, itemName);
        } catch (IOException e) {
            // Repo unreachable after the deletes? report what we know.
            after = new Version[0];
        }
        return new PurgeVersionsResponse(path, before.length, after.length, deleted,
            oldestDeleted, latestDeleted, lastVersionDeleted, isAdmin);
    }

    @Override
    public boolean needsProgram() {
        return false; // operates on the project repository, not a program
    }

    @Override
    public boolean mutates() {
        return true; // dispatcher check-in is gated on a non-null program, so this is safe (no program opened)
    }

    @Override
    public boolean requiresAdmin() {
        return true; // gated by RPC_ADMIN_PASSWORD
    }

    /** Summary of one purge pass. */
    static final class PurgeVersionsResponse extends RpcResponse {
        final String file;
        final int before;
        final int after;
        final int deleted;
        /** Version number of the first (oldest) revision removed; -1 if none. */
        final int oldestDeletedVersion;
        /** Version number of the last (most recent) revision removed; -1 if none. */
        final int latestDeletedVersion;
        /** True iff purge removed the last remaining version (the file itself is gone). */
        final boolean fileDeleted;
        /** True iff the calling Ghidra user is a repository admin. */
        final boolean isAdmin;

        PurgeVersionsResponse(String file, int before, int after, int deleted,
                int oldestDeletedVersion, int latestDeletedVersion,
                boolean fileDeleted, boolean isAdmin) {
            this.success = true;
            this.file = file;
            this.before = before;
            this.after = after;
            this.deleted = deleted;
            this.oldestDeletedVersion = oldestDeletedVersion;
            this.latestDeletedVersion = latestDeletedVersion;
            this.fileDeleted = fileDeleted;
            this.isAdmin = isAdmin;
        }
    }
}