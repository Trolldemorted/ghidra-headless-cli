package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure GetImports: list symbols this program imports from external
 * libraries. Mirrors the Ghidra Imports window — one group per library, each
 * with its imported entries (functions and data).
 *
 * <p>Request:
 * <pre>
 *   { "file": "&lt;path&gt;", "type": "all|function", "limit": 0 }
 * </pre>
 *
 * <p>{@code type} defaults to {@code all} (function + data imports). Use
 * {@code function} to skip non-function imports.
 *
 * <p>{@code limit} caps the TOTAL number of entries across all libraries; when
 * hit, {@code truncated} is set true and the iteration stops. The current
 * library is still emitted (possibly short).
 *
 * <p>Read-only — does not mutate the program or check anything back in.
 */
public final class GetImportsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String type = RpcContext.reqStr(req, "type").toLowerCase();
        if (!type.equals("all") && !type.equals("function")) {
            return RpcResponse.error(
                "Invalid 'type' '" + type + "': must be all or function.");
        }
        boolean functionsOnly = type.equals("function");
        int limit = RpcContext.reqInt(req, "limit");

        ExternalManager em = ctx.program().getExternalManager();
        String[] libraryNames = em.getExternalLibraryNames();
        List<ImportLibrary> libraries = new ArrayList<>();
        int total = 0;
        boolean truncated = false;

        for (String libName : libraryNames) {
            ctx.monitor().checkCancelled();
            List<ImportMatch> entries = new ArrayList<>();
            int libCount = 0;
            ExternalLocationIterator it = em.getExternalLocations(libName);
            while (it.hasNext()) {
                ctx.monitor().checkCancelled();
                ExternalLocation loc = it.next();
                boolean isFunc = loc.isFunction();
                if (functionsOnly && !isFunc) continue;

                Function f = isFunc ? loc.getFunction() : null;
                SourceType src = loc.getSource();
                if (src == SourceType.DEFAULT) continue;

                entries.add(new ImportMatch(
                    loc.getLabel(),
                    loc.getExternalSpaceAddress().toString(),
                    loc.getOriginalImportedName(),
                    src == null ? null : src.toString(),
                    isFunc
                ));
                if (f != null && f.isThunk()) {
                    // No-op — we just record the function-ness flag above.
                }
                libCount++;
                total++;
                if (limit > 0 && total >= limit) {
                    truncated = true;
                    break;
                }
            }
            if (!entries.isEmpty()) {
                libraries.add(new ImportLibrary(libName, libCount, entries));
            }
            if (truncated) break;
        }

        return new GetImportsResponse(total, libraries.size(), truncated, libraries);
    }

    @Override
    public boolean mutates() {
        return false;
    }
}
