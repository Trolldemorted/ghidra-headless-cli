package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Procedure NamespaceListClasses: list class namespaces under a parent.
 *
 * <p>Request: {@code { file, parent? , recursive? , limit? }}.
 * <ul>
 *   <li>{@code parent} — path of the namespace to start from; null/empty/"/"
 *       defaults to the program's global namespace.</li>
 *   <li>{@code recursive} — when true (default), descend into plain
 *       namespaces to find classes nested deeper. Stops descending into
 *       classes themselves (the GUI's Symbol Tree flattens class members
 *       but recurses into their sub-classes via the same logic).</li>
 *   <li>{@code limit} — cap on the number of classes returned. 0 (default)
 *       means unlimited. When the cap is hit, {@code truncated} is true
 *       and the walk stops early.</li>
 * </ul>
 *
 * <p>Only {@code GhidraClass} (i.e. namespaces whose type is CLASS) is
 * emitted; plain namespaces are not listed by this verb.
 *
 * <p>Read-only: the file is checked out by dispatch per policy but not
 * checked in (see {@code RpcContext.dispatch}). No transaction is opened.
 */
public final class NamespaceListClassesHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String parentPath = RpcContext.optStr(req, "parent");
        boolean recursive = RpcContext.reqBool(req, "recursive");
        int limit = RpcContext.reqInt(req, "limit");

        Namespace parent;
        try {
            parent = NamespaceResolve.resolve(ctx, parentPath);
        } catch (IllegalArgumentException e) {
            return RpcResponse.error(e.getMessage());
        }
        ctx.monitor().checkCancelled();

        List<ClassEntry> out = new ArrayList<>();
        boolean[] truncated = { false };
        walk(parent, recursive, limit, out, truncated, ctx);

        // Deterministic order: by path (BFS depth-first, then alphabetical
        // at each level). This mirrors the GUI's Symbol Tree view.
        out.sort(Comparator.comparing((ClassEntry e) -> e.path));
        return new NamespaceListClassesResponse(out.size(), truncated[0], out);
    }

    /**
     * Recursive walker. {@code out} is appended to in BFS-ish order
     * (depth-first so a parent class appears before its sub-classes).
     * {@code truncated[0]} is set to true if the limit is hit; the walk
     * then stops (we don't keep counting — limits are exact, not "at
     * least").
     */
    private void walk(Namespace ns, boolean recursive, int limit,
            List<ClassEntry> out, boolean[] truncated, RpcContext ctx) throws Exception {
        if (truncated[0]) {
            return;
        }
        SymbolTable st = ctx.program().getSymbolTable();
        // Iterate children; emit classes, descend into plain namespaces.
        List<Namespace> plainChildren = new ArrayList<>();
        for (Symbol sym : st.getSymbols(ns)) {
            ctx.monitor().checkCancelled();
            Object obj = sym.getObject();
            if (obj instanceof GhidraClass) {
                Namespace gc = (Namespace) obj;
                out.add(new ClassEntry(gc.getName(), slashPath(gc), slashPath(ns)));
                if (limit > 0 && out.size() >= limit) {
                    truncated[0] = true;
                    return;
                }
            } else if (recursive && obj instanceof Namespace) {
                // Plain namespace child — descend into it later.
                plainChildren.add((Namespace) obj);
            }
        }
        if (recursive && !truncated[0]) {
            // Recurse into plain namespace children so nested classes are
            // found. We sort children by name for deterministic output.
            plainChildren.sort(Comparator.comparing(Namespace::getName));
            for (Namespace child : plainChildren) {
                if (truncated[0]) {
                    return;
                }
                walk(child, recursive, limit, out, truncated, ctx);
            }
        }
    }

    /**
     * Render a namespace's full path as {@code "/Foo/Bar"} (matching the
     * {@code --class PATH} syntax used elsewhere in the CLI). Walks the
     * parent chain because {@code Namespace.getName(true)} returns
     * {@code "::"}-delimited paths that would surprise users.
     */
    private static String slashPath(Namespace ns) {
        Namespace root = ns.getParentNamespace();
        if (root == null) {
            return "/";
        }
        List<String> segs = new ArrayList<>();
        for (Namespace n = ns; n != null && n.getParentNamespace() != null; n = n.getParentNamespace()) {
            segs.add(0, n.getName());
        }
        StringBuilder sb = new StringBuilder();
        for (String s : segs) {
            sb.append('/').append(s);
        }
        return sb.toString();
    }

    @Override
    public boolean mutates() {
        return false;
    }

    /** One class entry: bare name, slash path, immediate parent's slash path. */
    static final class ClassEntry {
        final String name;
        final String path;
        final String parentPath;

        ClassEntry(String name, String path, String parentPath) {
            this.name = name;
            this.path = path;
            this.parentPath = parentPath;
        }
    }

    /** Success response for NamespaceListClasses. gson serializes all fields. */
    static final class NamespaceListClassesResponse extends RpcResponse {
        final int count;
        final boolean truncated;
        final List<ClassEntry> classes;

        NamespaceListClassesResponse(int count, boolean truncated, List<ClassEntry> classes) {
            this.success = true;
            this.count = count;
            this.truncated = truncated;
            this.classes = classes;
        }
    }
}
