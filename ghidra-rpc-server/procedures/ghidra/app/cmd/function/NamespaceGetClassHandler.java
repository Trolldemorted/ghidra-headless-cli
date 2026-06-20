package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Procedure NamespaceGetClass: get metadata for a class namespace.
 *
 * <p>Request: {@code { file, class }}. {@code class} is the full project path
 * of the class (e.g. {@code "/Game/OpMarketTrade"}); {@code "/"} (or
 * null/empty) resolves to the global namespace, which is NOT a class and so
 * returns an error. Resolution uses {@link NamespaceResolve}, which handles
 * {@code NamespaceUtils.getNamespaceByPath} with a recursive simple-name
 * fallback (matching the GUI's Symbol Tree lookup).
 *
 * <p>This verb only returns classes — passing a plain namespace's path
 * returns an error (mirrors the create/rename/delete verbs' symmetry).
 * The response is the same shape regardless of how the class was created
 * (fresh via {@code createClass}, or via {@code convertNamespaceToClass}).
 *
 * <p>Read-only: the file is checked out by dispatch per policy but not
 * checked in (see {@code RpcContext.dispatch}). No transaction is opened.
 */
public final class NamespaceGetClassHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String classPath = RpcContext.optStr(req, "class");
        if (classPath == null || classPath.isEmpty()) {
            return RpcResponse.error("Missing required field 'class'.");
        }

        Namespace ns;
        try {
            ns = NamespaceResolve.resolve(ctx, classPath);
        } catch (IllegalArgumentException e) {
            return RpcResponse.error(e.getMessage());
        }
        if (!(ns instanceof GhidraClass)) {
            return RpcResponse.error("'" + classPath
                + "' is not a class (it's a plain namespace); this verb only returns classes.");
        }
        ctx.monitor().checkCancelled();

        Symbol sym = ns.getSymbol();

        // memberCount: every function symbol whose parent namespace is this
        // class (the GUI's Symbol Tree "Functions" count for a class). Walk
        // the SymbolTable filtering to SymbolType.FUNCTION — there is no
        // FunctionManager.getFunctions(Namespace, boolean) overload.
        SymbolTable stForMembers = ctx.program().getSymbolTable();
        int memberCount = 0;
        for (Symbol child : stForMembers.getSymbols(ns)) {
            if (child.getSymbolType() == SymbolType.FUNCTION) {
                memberCount++;
            }
        }

        // childNamespaceCount: every immediate child whose symbol type is
        // NAMESPACE or CLASS. Namespace.getNamespaces() is not a public API;
        // walk the SymbolTable like NamespaceResolve.children() does.
        SymbolTable st = ctx.program().getSymbolTable();
        int childNamespaceCount = 0;
        for (Symbol child : st.getSymbols(ns)) {
            if (child.getSymbolType().isNamespace()) {
                childNamespaceCount++;
            }
        }

        // The class's body address. For a class, the namespace's underlying
        // symbol's address is the anchor (entry point of the auto-stubbed
        // struct, or the function-body address if the class was converted
        // from a function namespace). Namespace.getBody() is null/empty for
        // non-function namespaces, so go through the symbol.
        String bodyAddress = sym.getAddress() == null ? null : sym.getAddress().toString();

        return new NamespaceGetClassResponse(
            ns.getName(),                              // bare name
            slashPath(ns),                             // slash-delimited full path
            parentSlashPath(ns),                       // slash-delimited parent path
            true,                                      // isClass (always true here)
            sym.getSource() == null ? null : sym.getSource().toString(),
            ns.getID(),
            memberCount,
            childNamespaceCount,
            bodyAddress);
    }

    /**
     * Render a namespace's full path as {@code "/Foo/Bar"} (matching the
     * {@code --class PATH} syntax used elsewhere in the CLI). The default
     * {@code Namespace.getName(true)} returns {@code "::"}-delimited paths
     * which would surprise users.
     */
    private static String slashPath(Namespace ns) {
        Namespace root = ns.getParentNamespace();
        if (root == null) {
            return "/";
        }
        StringBuilder sb = new StringBuilder();
        // Walk the parent chain to build the path. Use getPathList to get
        // the segments in order from root to leaf; join with "/".
        java.util.List<String> segs = new java.util.ArrayList<>();
        for (Namespace n = ns; n != null && n.getParentNamespace() != null; n = n.getParentNamespace()) {
            segs.add(0, n.getName());
        }
        for (String s : segs) {
            sb.append('/').append(s);
        }
        return sb.toString();
    }

    /** Like {@link #slashPath} but for the parent namespace; returns "/" for top-level. */
    private static String parentSlashPath(Namespace ns) {
        Namespace parent = ns.getParentNamespace();
        return parent == null ? "/" : slashPath(parent);
    }

    @Override
    public boolean mutates() {
        return false;
    }

    /** Success response for NamespaceGetClass. gson serializes all fields. */
    static final class NamespaceGetClassResponse extends RpcResponse {
        final String name;
        final String path;
        final String parentPath;
        final boolean isClass;
        final String source;
        final long id;
        final int memberCount;
        final int childNamespaceCount;
        final String bodyAddress;

        NamespaceGetClassResponse(String name, String path, String parentPath,
                boolean isClass, String source, long id, int memberCount,
                int childNamespaceCount, String bodyAddress) {
            this.success = true;
            this.name = name;
            this.path = path;
            this.parentPath = parentPath;
            this.isClass = isClass;
            this.source = source;
            this.id = id;
            this.memberCount = memberCount;
            this.childNamespaceCount = childNamespaceCount;
            this.bodyAddress = bodyAddress;
        }
    }
}
