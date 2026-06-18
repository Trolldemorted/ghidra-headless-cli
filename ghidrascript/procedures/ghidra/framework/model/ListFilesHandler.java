package procedures.ghidra.framework.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;

/**
 * Procedure ListFiles: enumerate the project's files under a folder.
 *
 * Project-level and read-only ({@link #needsProgram()} = false, {@link #mutates()} = false):
 * it walks the {@link DomainFolder} tree via {@link ProjectData}, never opening or checking
 * out any program. {@code folder} (default "/") scopes the walk; {@code recursive} (default
 * true) descends into subfolders; {@code includeFolders} (default false) also emits folder
 * entries; {@code contentType} (optional) keeps only files of that content type (e.g.
 * "Program", case-insensitive). An optional {@code limit} caps results and sets
 * {@code truncated}. Entries are returned sorted by path.
 */
public final class ListFilesHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        if (ctx.project() == null) {
            return RpcResponse.error("No project is available; cannot list files.");
        }
        String folderPath = normalize(RpcContext.optStr(req, "folder"));
        boolean recursive = RpcContext.optBool(req, "recursive", true);
        boolean includeFolders = RpcContext.optBool(req, "includeFolders", false);
        String contentType = RpcContext.optStr(req, "contentType");
        int limit = RpcContext.optInt(req, "limit", 0);

        ProjectData data = ctx.project().getProjectData();
        DomainFolder folder = data.getFolder(folderPath);
        if (folder == null) {
            return RpcResponse.error("No folder found for '" + folderPath + "'.");
        }

        List<FileEntry> entries = new ArrayList<>();
        collect(folder, recursive, includeFolders, contentType, entries, ctx);
        entries.sort(Comparator.comparing(e -> e.path));

        boolean truncated = false;
        if (limit > 0 && entries.size() > limit) {
            entries = new ArrayList<>(entries.subList(0, limit));
            truncated = true;
        }
        return new ListFilesResponse(entries.size(), truncated, entries);
    }

    @Override
    public boolean needsProgram() {
        return false; // walks the project tree; opens/checks out nothing
    }

    @Override
    public boolean mutates() {
        return false;
    }

    private void collect(DomainFolder folder, boolean recursive, boolean includeFolders,
            String contentType, List<FileEntry> out, RpcContext ctx) throws Exception {
        for (DomainFile f : folder.getFiles()) {
            ctx.monitor().checkCancelled();
            if (contentType != null && !contentType.equalsIgnoreCase(f.getContentType())) {
                continue;
            }
            out.add(FileEntry.file(f));
        }
        for (DomainFolder sub : folder.getFolders()) {
            ctx.monitor().checkCancelled();
            if (includeFolders) {
                out.add(FileEntry.folder(sub));
            }
            if (recursive) {
                collect(sub, recursive, includeFolders, contentType, out, ctx);
            }
        }
    }

    /** Normalize a folder path to a leading-slash, no-trailing-slash form ("/" stays "/"). */
    private static String normalize(String path) {
        String f = (path == null || path.trim().isEmpty()) ? "/" : path.trim();
        if (!f.startsWith("/")) {
            f = "/" + f;
        }
        if (f.length() > 1 && f.endsWith("/")) {
            f = f.substring(0, f.length() - 1);
        }
        return f;
    }

    /** One project entry. File-only attributes are boxed so folders omit them (gson skips null). */
    static final class FileEntry {
        final String path;
        final String name;
        final boolean isFolder;
        final String contentType;
        final Integer version;
        final Boolean versioned;
        final Boolean checkedOut;

        private FileEntry(String path, String name, boolean isFolder, String contentType,
                Integer version, Boolean versioned, Boolean checkedOut) {
            this.path = path;
            this.name = name;
            this.isFolder = isFolder;
            this.contentType = contentType;
            this.version = version;
            this.versioned = versioned;
            this.checkedOut = checkedOut;
        }

        static FileEntry file(DomainFile f) {
            return new FileEntry(f.getPathname(), f.getName(), false, f.getContentType(),
                f.getVersion(), f.isVersioned(), f.isCheckedOut());
        }

        static FileEntry folder(DomainFolder d) {
            return new FileEntry(d.getPathname(), d.getName(), true, null, null, null, null);
        }
    }

    /** Success response carrying the file listing. */
    static final class ListFilesResponse extends RpcResponse {
        final int count;
        final boolean truncated;
        final List<FileEntry> files;

        ListFilesResponse(int count, boolean truncated, List<FileEntry> files) {
            this.success = true;
            this.count = count;
            this.truncated = truncated;
            this.files = files;
        }
    }
}
