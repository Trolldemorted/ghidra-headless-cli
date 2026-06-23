package procedures.ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Procedure NamespaceDeleteClass: remove a class namespace symbol.
 *
 * <p>Request: {@code { file, class }}.
 * {@code class} is the class's full path (e.g. "/Game/MyClass").
 *
 * <p>Removes only the class symbol. Does NOT delete the struct in the
 * program's Data Type Manager. Class and struct are independent — sharing
 * only a name — so deleting the class leaves the struct (and any
 * associated auto-stub or user-created struct) untouched. If the user
 * wants the struct gone too, call {@code DeleteDataType} separately.
 *
 * <p>If {@code class} points to a plain namespace (not a class), the
 * request is rejected — this verb only deletes classes. Use a future
 * {@code NamespaceDeleteNamespace} (out of scope this round) for plain
 * namespaces.
 *
 * <p><b>Function-member preservation.</b> Ghidra's
 * {@link SymbolTable#removeSymbolSpecial} on a class symbol destroys the
 * class AND its function members (the function objects themselves are
 * removed; only the entry-point label survives, with no body — verified
 * 2026-06-23 by reproducing on P3 against
 * {@code /Mapeditor.exe}: after {@code namespace delete-class
 * /DeleteClassBugTest}, {@code function decompile --address 0x4011f0}
 * returned {@code "No function matched '0x4011f0'... A Data unit (not
 * code) is defined at that address"}). To prevent that data loss, this
 * handler detaches EVERY function descendant of the class (recursively
 * through sub-classes and sub-namespaces) to the class's parent
 * namespace BEFORE deleting the class. The functions survive intact
 * (calling convention, signature, body, tags all preserved) as orphans
 * under the parent; sub-namespaces and sub-classes are deleted along
 * with the class. This matches the documented intent of the
 * {@code 0.1.0} quirks-log fix ("child functions survive as orphans").
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class NamespaceDeleteClassHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String classPath = RpcContext.reqStr(req, "class");

        Namespace resolved = NamespaceResolve.resolve(ctx, classPath);
        if (!(resolved instanceof GhidraClass)) {
            return RpcResponse.error("'" + classPath + "' is not a class (it's a plain namespace); "
                + "this verb only deletes classes.");
        }
        GhidraClass gc = (GhidraClass) resolved;
        Symbol sym = gc.getSymbol();
        Namespace parent = gc.getParentNamespace();

        String[] error = { null };
        try {
            ctx.runWrite("namespace delete-class " + classPath, () -> {
                try {
                    // 1) Re-parent every function descendant of the class to
                    //    the class's parent namespace. Snapshot first so the
                    //    iterator isn't invalidated by the re-parenting.
                    detachFunctionDescendants(ctx, gc, parent);
                    // 2) Now the class subtree has no function members;
                    //    removeSymbolSpecial deletes the class (and the
                    //    empty sub-namespaces / sub-classes).
                    ctx.program().getSymbolTable().removeSymbolSpecial(sym);
                } catch (Exception e) {
                    error[0] = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                }
            });
        } catch (Exception e) {
            return RpcResponse.error(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
        if (error[0] != null) {
            return RpcResponse.error(error[0]);
        }
        return new NamespaceDeleteClassResponse(classPath);
    }

    /**
     * Walk the namespace subtree rooted at {@code ns}; for every function
     * found, re-parent to {@code reparentTo}. Recurses into sub-namespaces
     * (plain AND class) so nested functions are preserved too. Sub-namespaces
     * themselves are not preserved — they're deleted along with the class
     * (the user's complaint is specifically about functions).
     *
     * <p>Snapshot the children up front because {@code setParentNamespace}
     * mutates the symbol table and would invalidate a live iterator.
     */
    private static void detachFunctionDescendants(RpcContext ctx, Namespace ns, Namespace reparentTo)
            throws DuplicateNameException, InvalidInputException, CircularDependencyException {
        SymbolTable st = ctx.program().getSymbolTable();
        List<Symbol> snapshot = new ArrayList<>();
        for (Symbol child : st.getSymbols(ns)) {
            snapshot.add(child);
        }
        for (Symbol child : snapshot) {
            Object obj = child.getObject();
            if (obj instanceof Function) {
                ((Function) obj).setParentNamespace(reparentTo);
            }
            else if (obj instanceof Namespace) {
                // Recurse into both plain sub-namespaces and sub-classes.
                // Function members found deeper are still re-parented to
                // the TOP-level `reparentTo` (e.g. the root namespace) —
                // pulling them OUT of the deleted subtree — so they're
                // safe when the cascading removeSymbolSpecial deletes the
                // intermediate namespaces.
                detachFunctionDescendants(ctx, (Namespace) obj, reparentTo);
            }
        }
    }

    @Override
    public boolean mutates() {
        return true;
    }

    /** Success response carrying the deleted class's former path. */
    static final class NamespaceDeleteClassResponse extends RpcResponse {
        final String path;

        NamespaceDeleteClassResponse(String path) {
            this.success = true;
            this.path = path;
        }
    }
}
