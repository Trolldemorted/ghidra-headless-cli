package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Procedure NamespaceRenameClass: rename a class namespace.
 *
 * <p>Request: {@code { file, class, name, source? }}.
 * {@code class} is the class's current full path (e.g. "/Game/OldName").
 * {@code name} is the new bare name (no slash).
 *
 * <p>PURE NAMESPACE RENAME. Does NOT touch the program's Data Type Manager.
 * If a struct with the old name exists, it stays; if the decompiler needs
 * to resolve {@code this} by class name, the user must rename the struct
 * separately via {@code EditDataType} (or keep both names in sync). Class
 * and struct are coupled by NAME only — see
 * {@code FunctionDB.createClassStructIfNeeded}.
 *
 * <p>Renames via {@code GhidraClass.getSymbol().setName(name, sourceType)},
 * which goes through the public Symbol API. (GhidraClassDB.setName also
 * exists but is package-private to {@code ghidra.program.database.symbol}.)
 *
 * <p>{@code source} (optional, defaults to {@code USER_DEFINED},
 * case-insensitive).
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class NamespaceRenameClassHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String classPath = RpcContext.reqStr(req, "class");
        String newName = RpcContext.reqStr(req, "name");
        if (newName.contains("/")) {
            return RpcResponse.error("'name' must be a bare name (no '/'); pass the parent via 'class'.");
        }
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        Namespace resolved = NamespaceResolve.resolve(ctx, classPath);
        if (!(resolved instanceof GhidraClass)) {
            return RpcResponse.error("'" + classPath + "' is not a class (it's a plain namespace); "
                + "use namespace create-class --from-namespace to convert it first.");
        }
        GhidraClass gc = (GhidraClass) resolved;
        Symbol sym = gc.getSymbol();

        String[] error = { null };
        try {
            ctx.runWrite("namespace rename-class " + classPath, () -> {
                try {
                    // Public Symbol.setName(String, SourceType). It throws
                    // DuplicateNameException if the new name collides with
                    // another namespace at the same level; the catch below
                    // surfaces that as a normal error response.
                    sym.setName(newName, source);
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
        // After rename, the GhidraClass wrapper around the symbol may still
        // hold the old name. Re-resolve by path to get the post-rename view.
        String newPath = newName + (classPath.contains("/")
            ? classPath.substring(0, classPath.lastIndexOf('/'))
            : "");
        Namespace after = NamespaceResolve.resolve(ctx, newPath);
        return new NamespaceRenameClassResponse(
            after.getName(true),
            after.getParentNamespace().getName(true));
    }

    @Override
    public boolean mutates() {
        return true;
    }

    /** Success response carrying the renamed class's path and parent path. */
    static final class NamespaceRenameClassResponse extends RpcResponse {
        final String path;
        final String parentPath;

        NamespaceRenameClassResponse(String path, String parentPath) {
            this.success = true;
            this.path = path;
            this.parentPath = parentPath;
        }
    }
}
