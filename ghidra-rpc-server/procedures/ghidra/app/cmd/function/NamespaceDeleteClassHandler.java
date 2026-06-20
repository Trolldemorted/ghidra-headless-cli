package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

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
 * <p>Children of the class (functions, sub-namespaces) become orphans
 * under the parent namespace, matching the GUI's right-click → Delete on
 * a class in the Symbol Tree.
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

        String[] error = { null };
        try {
            ctx.runWrite("namespace delete-class " + classPath, () -> {
                try {
                    SymbolTable st = ctx.program().getSymbolTable();
                    // removeSymbolSpecial handles namespace symbols correctly;
                    // plain removeSymbol refuses them. This matches what the
                    // SymbolTreeProvider's delete action does.
                    st.removeSymbolSpecial(sym);
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
