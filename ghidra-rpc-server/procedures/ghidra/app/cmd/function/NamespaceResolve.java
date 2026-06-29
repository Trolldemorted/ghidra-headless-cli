package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;

import procedures.RpcContext;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Shared namespace resolver used by the Namespace* and
 * FunctionSetClassAssociation procedures.
 *
 * <p>Resolves a path like "/Game/Sub" to the corresponding {@link Namespace}
 * via {@link NamespaceUtils#getNamespaceByPath}.
 *
 * <p>STRICT: there is no recursive simple-name fallback. If
 * {@code getNamespaceByPath} returns zero matches, the resolver walks the
 * namespace tree once to collect up to 5 leaf-name candidates and surfaces
 * them in the {@link IllegalArgumentException} as a "did you mean ...?"
 * hint. The caller is expected to correct the path on the next attempt.
 *
 * <p>Why strict: a previous lenient fallback matched a namespace by its
 * simple name across the entire namespace subtree (e.g. request
 * {@code "/input/<prog>/<lib>.dll"} silently resolved to whatever
 * file's parent happened to be named that). Strict lookup makes the
 * missing match visible to the caller instead of operating on the wrong
 * namespace.
 *
 * <p>Package-private by design: only the Namespace* and
 * FunctionSetClassAssociation handlers in this package use it.
 */
final class NamespaceResolve {

    /** Cap on the number of "did you mean" candidates surfaced. */
    private static final int MAX_CANDIDATES = 5;

    private NamespaceResolve() { }

    /**
     * Resolve a namespace by its project path. The bare path "/" (or null /
     * empty) resolves to the program's global namespace. On zero matches
     * from {@link NamespaceUtils#getNamespaceByPath}, throws with a
     * "did you mean ..." hint built from leaf-name candidates. On multiple
     * matches, throws (ambiguous).
     */
    static Namespace resolve(RpcContext ctx, String path) {
        Namespace root = ctx.program().getGlobalNamespace();
        // Short-circuit the global namespace: NamespaceUtils.getNamespaceByPath
        // can't resolve "/" because SymbolPath("/") is non-empty.
        if (path == null || path.isEmpty() || path.equals("/")) {
            return root;
        }
        // NamespaceUtils.getNamespaceByPath only accepts "::" as a path
        // separator (SymbolPathParser: input containing "::" is parsed
        // by that delimiter; otherwise the whole input is one segment).
        // Users type "/" everywhere else in the CLI ("--class /Game/Foo",
        // "--file /Mapeditor.exe"); translate each "/" to "::" and drop
        // any leading "/". Bare names (no slashes) work as-is.
        // (We DON'T fall back to a leaf-name search — that's the silent-
        // rewrite bug we're eliminating. We just translate the form so a
        // well-intentioned request resolves.)
        String lookupPath = path.startsWith("/") ? path.substring(1) : path;
        lookupPath = lookupPath.replace("/", "::");
        List<Namespace> matches = NamespaceUtils.getNamespaceByPath(ctx.program(), root, lookupPath);
        if (matches.size() == 1) {
            return matches.get(0);
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Multiple namespaces matched '" + path
                + "'; pass the full project path (e.g. '/Game/Foo').");
        }
        // Zero matches: build a leaf-name candidate hint and throw.
        String simpleName = path.contains("/")
            ? path.substring(path.lastIndexOf('/') + 1)
            : path;
        List<String> candidates = new ArrayList<>();
        collectNameCandidates(ctx, root, simpleName, candidates, MAX_CANDIDATES);
        throw new IllegalArgumentException(noMatchMessage(path, simpleName, candidates));
    }

    /**
     * Walk a namespace subtree; append up to {@code limit} child namespaces
     * (recursive into NAMESPACE and CLASS children) whose bare name matches
     * {@code name}. Used only for the "did you mean ..." hint.
     */
    private static void collectNameCandidates(RpcContext ctx, Namespace parent, String name,
            List<String> out, int limit) {
        // Namespace has no getSymbolTable(); route through the program.
        SymbolTable st = ctx.program().getSymbolTable();
        for (Symbol sym : st.getSymbols(parent)) {
            if (out.size() >= limit) {
                return;
            }
            Object obj = sym.getObject();
            if (!(obj instanceof Namespace)) {
                continue;
            }
            Namespace child = (Namespace) obj;
            if (child.getName().equals(name)) {
                // Slash-delimited path so the candidate is drop-in usable
                // as the next --class PATH argument.
                out.add(slashPath(child));
                continue;
            }
            collectNameCandidates(ctx, child, name, out, limit);
        }
    }

    /**
     * Render a namespace's full path as {@code "/Foo/Bar"} (matching the
     * {@code --class PATH} syntax used elsewhere in the CLI). Walks the
     * parent chain because {@code Namespace.getName(true)} returns
     * {@code "::"}-delimited paths that would surprise users.
     */
    private static String slashPath(Namespace ns) {
        if (ns.getParentNamespace() == null) {
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

    private static String noMatchMessage(String path, String simpleName, List<String> candidates) {
        if (candidates.isEmpty()) {
            return "No namespace found for '" + path + "'.";
        }
        StringBuilder sb = new StringBuilder("No namespace found for '");
        sb.append(path).append("'. Did you mean ");
        for (int i = 0; i < candidates.size(); i++) {
            if (i > 0) {
                sb.append(i == candidates.size() - 1 ? " or " : ", ");
            }
            sb.append('\'').append(candidates.get(i)).append('\'');
        }
        sb.append("?");
        return sb.toString();
    }
}
