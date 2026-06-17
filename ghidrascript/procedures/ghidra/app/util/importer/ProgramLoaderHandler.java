package procedures.ghidra.app.util.importer;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Procedure ProgramLoader: import a new program into the project from bytes carried in
 * the request. Ghidra runs on a separate machine from the client, so the file travels
 * inside the JSON request as base64 ({@code "bytes"}) rather than as a server-side path.
 *
 * Wraps Ghidra's {@link ProgramLoader} builder ({@code source(byte[]).name(...).load()});
 * the loader is chosen by best guess from the content. {@link LoadResults} is closed via
 * try-with-resources, which releases the loaded program(s).
 *
 * This is a PROJECT-level procedure ({@link #needsProgram()} = false): it takes no
 * {@code "program"} field. It persists the result itself — save into the project, then
 * (in a shared repository) add to version control so other clients see it — so it is not
 * routed through the dispatch check-in path ({@link #mutates()} = false). Like every
 * procedure it runs under the single dispatch lock, so the import is serialized against
 * all other program access.
 *
 * Request: {@code {"procedure":"ProgramLoader","name":"foo.exe","bytes":"<base64>",
 * "folder":"/imports","comment":"..."}} — {@code folder} defaults to "/", {@code comment}
 * to a generated message.
 */
public final class ProgramLoaderHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String name = baseName(RpcContext.reqStr(req, "name"));
        byte[] bytes = decode(RpcContext.optStr(req, "bytes"));
        String folderPath = normalizeFolder(RpcContext.optStr(req, "folder"));
        String comment = RpcContext.optStr(req, "comment");
        if (comment == null || comment.isEmpty()) {
            comment = "RPC import " + name;
        }

        Project project = ctx.project();
        if (project == null) {
            return RpcResponse.error("No project is available; cannot import '" + name + "'.");
        }
        TaskMonitor monitor = ctx.monitor();
        ensureFolder(project, folderPath);

        MessageLog log = new MessageLog();
        // Give the ByteProvider a name: the source(byte[]) overload leaves it null, which
        // NPEs loaders that sniff by filename (GZF/GDT/Tenet). name() sets the program name.
        try (ByteProvider provider = new ByteArrayProvider(name, bytes);
                LoadResults<Program> results = ProgramLoader.builder()
                .source(provider)
                .name(name)
                .project(project)
                .projectFolderPath(folderPath)
                .log(log)
                .monitor(monitor)
                .load()) {
            Loaded<Program> primaryLoaded = results.getPrimary();
            List<String> imported = new ArrayList<>();
            String primary = null;
            for (Loaded<Program> loaded : results) {
                DomainFile df = loaded.save(monitor); // create the file in the project
                // In a shared repository a freshly created file is local-only until added
                // to version control; push it so every other client sees it immediately.
                if (df.canAddToRepository() && !df.isVersioned()) {
                    df.addToVersionControl(comment, false, monitor);
                }
                imported.add(df.getPathname());
                if (loaded == primaryLoaded) {
                    primary = df.getPathname();
                }
            }
            // apply() hands us the program without taking a consumer to release (the
            // no-arg getDomainObject() is deprecated-for-removal).
            String[] format = {null};
            if (primaryLoaded != null) {
                primaryLoaded.apply(p -> format[0] = p.getExecutableFormat());
            }
            return new ImportResponse(imported, primary, format[0]);
        } catch (LoadException | LanguageNotFoundException | VersionException e) {
            String detail = log.hasMessages() ? " [" + log.toString().trim() + "]" : "";
            return RpcResponse.error("Import failed for '" + name + "': " + message(e) + detail);
        }
    }

    /** Project-wide operation: no per-request program. */
    @Override
    public boolean needsProgram() {
        return false;
    }

    /** Persistence (save + add-to-version-control) is handled here, not by dispatch. */
    @Override
    public boolean mutates() {
        return false;
    }

    /** The program name is a plain file name; drop any directory part a client included. */
    private static String baseName(String name) {
        String t = name.trim().replace('\\', '/');
        int slash = t.lastIndexOf('/');
        String base = (slash >= 0) ? t.substring(slash + 1) : t;
        if (base.isEmpty()) {
            throw new IllegalArgumentException("Field 'name' must be a non-empty file name.");
        }
        return base;
    }

    private static byte[] decode(String b64) {
        if (b64 == null || b64.isEmpty()) {
            throw new IllegalArgumentException("Missing required field 'bytes' (base64 file content).");
        }
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Field 'bytes' is not valid base64: " + e.getMessage());
        }
    }

    /** Default "/", ensure a single leading slash and no trailing slash. */
    private static String normalizeFolder(String path) {
        if (path == null || path.trim().isEmpty()) {
            return "/";
        }
        String t = path.trim();
        if (!t.startsWith("/")) {
            t = "/" + t;
        }
        while (t.length() > 1 && t.endsWith("/")) {
            t = t.substring(0, t.length() - 1);
        }
        return t;
    }

    /** Create every missing folder along {@code path} (root always exists). */
    private static void ensureFolder(Project project, String path) throws Exception {
        DomainFolder folder = project.getProjectData().getRootFolder();
        for (String part : path.split("/")) {
            if (part.isEmpty()) {
                continue;
            }
            DomainFolder next = folder.getFolder(part);
            folder = (next != null) ? next : folder.createFolder(part);
        }
    }

    private static String message(Throwable t) {
        String m = t.getMessage();
        return (m != null && !m.isEmpty()) ? m : t.getClass().getSimpleName();
    }

    /** Success response: project paths of the created program(s) plus the primary's format. */
    static final class ImportResponse extends RpcResponse {
        final List<String> imported;
        final String primary;
        final String format;

        ImportResponse(List<String> imported, String primary, String format) {
            this.success = true;
            this.imported = imported;
            this.primary = primary;
            this.format = format;
        }
    }
}
