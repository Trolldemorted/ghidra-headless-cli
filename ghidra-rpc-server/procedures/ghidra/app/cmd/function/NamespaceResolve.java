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
 * via {@link NamespaceUtils#getNamespaceByPath}, which understands both full
 * project paths and bare names (matching the GUI's Symbol Tree lookup).
 *
 * <p>Falls back to a recursive simple-name search when the path lookup
 * returns no matches — mirrors {@link RpcContext}'s program-resolution
 * fallback so users can pass either "/Foo/Bar" or "Bar" interchangeably,
 * and also covers cases where a freshly-created namespace in this same
 * session isn't yet visible to {@code getNamespaceByPath}.
 *
 * <p>Children of a namespace are enumerated via
 * {@link SymbolTable#getSymbols(Namespace)} filtered to symbols whose type
 * is {@code NAMESPACE} — Ghidra's {@code Namespace} interface has no public
 * {@code getNamespaces()} method, so we go through the SymbolTable.
 *
 * <p>Package-private by design: only the Namespace* and
 * FunctionSetClassAssociation handlers in this package use it.
 */
final class NamespaceResolve {

    private NamespaceResolve() {}

    /**
     * Resolve a namespace by its project path. The bare path "/" (or null /
     * empty) resolves to the program's global namespace. On no match, falls
     * back to recursive simple-name search; on ambiguity (multiple matches
     * for the same simple name at different paths), throws.
     */
    static Namespace resolve(RpcContext ctx, String path) {
        Namespace root = ctx.program().getGlobalNamespace();
        // Short-circuit the global namespace: NamespaceUtils.getNamespaceByPath
        // can't resolve "/" because SymbolPath("/") is non-empty, and passing
        // null/"" requires careful handling of the program/parent args.
        if (path == null || path.isEmpty() || path.equals("/")) {
            return root;
        }
        List<Namespace> matches = NamespaceUtils.getNamespaceByPath(ctx.program(), root, path);
        if (matches.size() == 1) {
            return matches.get(0);
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Multiple namespaces matched '" + path
                + "'; pass the full project path (e.g. '/Game/Foo').");
        }
        // Fallback: recursive search by simple name (the leaf segment).
        String simpleName = path.contains("/")
            ? path.substring(path.lastIndexOf('/') + 1)
            : path;
        Namespace found = findByNameRecursive(ctx, root, simpleName);
        if (found == null) {
            throw new IllegalArgumentException("No namespace found for '" + path + "'.");
        }
        return found;
    }

    /**
     * Recursively search a namespace subtree for a child with the given
     * simple name. Uses the program's SymbolTable directly so we don't
     * depend on each namespace having a backing symbol.
     */
    private static Namespace findByNameRecursive(RpcContext ctx, Namespace parent, String name) {
        SymbolTable st = ctx.program().getSymbolTable();
        for (Namespace child : children(parent, st)) {
            if (child.getName().equals(name)) {
                return child;
            }
            Namespace hit = findByNameRecursive(ctx, child, name);
            if (hit != null) {
                return hit;
            }
        }
        return null;
    }

    /**
     * Enumerate child namespaces of {@code parent} (one level only). Used
     * by the recursive-name fallback. Both {@code NAMESPACE} and {@code
     * CLASS} symbol types are considered (a class is a namespace whose type
     * is CLASS).
     */
    private static Iterable<Namespace> children(Namespace parent, SymbolTable st) {
        List<Namespace> out = new ArrayList<>();
        for (Symbol sym : st.getSymbols(parent)) {
            if (sym.getSymbolType().isNamespace()) {
                Object obj = sym.getObject();
                if (obj instanceof Namespace) {
                    out.add((Namespace) obj);
                }
            }
        }
        return out;
    }
}
