package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

/**
 * Procedure NamespaceCreateClass: create a new class namespace, or convert an
 * existing plain namespace into a class.
 *
 * <p>Request: {@code { file, parent? | fromNamespace, name? }}.
 *
 * <p>Exactly one of {@code parent} (the path of an existing namespace under
 * which to create a fresh class) or {@code fromNamespace} (the path of an
 * existing plain namespace whose type flips to CLASS) must be supplied. If
 * neither is supplied, the request is rejected with a clear error.
 *
 * <p>{@code name} is required when {@code parent} is used (the new class's
 * bare name). When {@code fromNamespace} is used, {@code name} is ignored —
 * the converted namespace keeps its existing name.
 *
 * <p>{@code source} (optional, defaults to {@code USER_DEFINED},
 * case-insensitive) is the {@link SourceType} for the new symbol.
 *
 * <p>This does NOT touch the program's Data Type Manager. Class names are
 * resolved against the DTM by name at decompile time (see
 * {@code FunctionDB.createClassStructIfNeeded}); associating a function
 * with a class whose name has no matching struct auto-stubs one. See
 * {@code FunctionSetClassAssociationHandler}.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class NamespaceCreateClassHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String parentPath = RpcContext.optStr(req, "parent");
        String fromNamespace = RpcContext.optStr(req, "fromNamespace");
        String name = RpcContext.optStr(req, "name");
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));

        boolean hasParent = parentPath != null && !parentPath.isEmpty();
        boolean hasFrom = fromNamespace != null && !fromNamespace.isEmpty();
        if (hasParent == hasFrom) {
            // both null/empty OR both set
            return RpcResponse.error("Exactly one of 'parent' or 'fromNamespace' is required.");
        }
        if (hasParent && (name == null || name.isEmpty())) {
            return RpcResponse.error("'name' is required when creating a class under 'parent'.");
        }

        SymbolTable st = ctx.program().getSymbolTable();
        GhidraClass[] result = { null };
        String[] error = { null };
        try {
            ctx.runWrite("namespace create-class " + (hasParent ? name : fromNamespace), () -> {
                try {
                    if (hasParent) {
                        Namespace parent = NamespaceResolve.resolve(ctx, parentPath);
                        result[0] = st.createClass(parent, name, source);
                    } else {
                        Namespace existing = NamespaceResolve.resolve(ctx, fromNamespace);
                        if (existing instanceof GhidraClass) {
                            error[0] = "'" + fromNamespace
                                + "' is already a class; use rename-class to change its name.";
                            return;
                        }
                        result[0] = st.convertNamespaceToClass(existing);
                    }
                } catch (InvalidInputException | IllegalArgumentException e) {
                    error[0] = e.getMessage();
                }
            });
        } catch (Exception e) {
            return RpcResponse.error(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
        if (error[0] != null) {
            return RpcResponse.error(error[0]);
        }
        GhidraClass gc = result[0];
        return new NamespaceCreateClassResponse(
            gc.getName(true),
            gc.getParentNamespace().getName(true));
    }

    @Override
    public boolean mutates() {
        return true;
    }

    /** Success response carrying the new class's path and parent path. */
    static final class NamespaceCreateClassResponse extends RpcResponse {
        final String path;
        final String parentPath;

        NamespaceCreateClassResponse(String path, String parentPath) {
            this.success = true;
            this.path = path;
            this.parentPath = parentPath;
        }
    }
}
