package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;

/**
 * Procedure FunctionSetClassAssociation: associate a function with a class —
 * the CLI equivalent of the GUI's "Edit → Set Class Association…".
 *
 * <p>Request: {@code { file, address, class }}.
 * {@code address} is the function's entry-point address.
 * {@code class} is the full path of the class namespace
 * (e.g. "/Game/OpMarketTrade").
 *
 * <p>After association, the decompiler types the function's implicit
 * {@code this} parameter (for {@code __thiscall} / MSVC member functions
 * on x86) as a pointer to the DTM type whose name matches the class. The
 * lookup is name-based: class and struct are coupled by name only.
 *
 * <p><b>Auto-stub warning:</b> if no struct with the class's name exists
 * in the program's DTM, Ghidra's {@code FunctionDB.createClassStructIfNeeded}
 * auto-creates a stub (size 0/1, no fields) on this edit. The stub is a
 * placeholder — populate it with {@code EditDataType} after the fact, or
 * prevent it by creating a struct with the class's name BEFORE running
 * this command. The auto-stub is also triggered by any subsequent edit
 * to an already-associated function (e.g. changing the calling convention
 * to {@code __thiscall}) — not just by this command.
 *
 * <p>Rejects plain namespaces as targets — only {@link GhidraClass}
 * instances are valid.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class FunctionSetClassAssociationHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String classPath = RpcContext.reqStr(req, "class");

        Function function = ctx.requireFunctionAt(entry);
        Namespace resolved;
        try {
            resolved = NamespaceResolve.resolve(ctx, classPath, true);
        } catch (IllegalArgumentException e) {
            // The user wanted to associate with a class. If a DTM
            // struct of the same leaf name exists, the common
            // mistake is forgetting `namespace create-class` first
            // (the struct and the class are coupled by name only;
            // we need the class namespace BEFORE we can associate).
            // Surface that directly — the generic
            // "No namespace found for 'X'" leaves the user guessing.
            String leaf = classPath.contains("/")
                ? classPath.substring(classPath.lastIndexOf('/') + 1) : classPath;
            if (!leaf.isEmpty() && dtmHasTypeNamed(ctx, leaf)) {
                return RpcResponse.error(
                    "No class namespace found for '" + classPath
                    + "' (a struct/type named '" + leaf + "' exists in the program's DTM, "
                    + "but a class is a different symbol-table object). "
                    + "Create the class first via "
                    + "`namespace create-class --parent / --name " + leaf + "`, "
                    + "then re-run `function set-class-association --class /" + leaf + "`. "
                    + "The class's DTM struct is coupled to the class by name "
                    + "(the decompiler retypes the implicit `this` from it).");
            }
            return RpcResponse.error(e.getMessage());
        }
        if (!(resolved instanceof GhidraClass)) {
            return RpcResponse.error("'" + classPath + "' is not a class (it's a plain namespace); "
                + "create the class first via namespace create-class.");
        }
        GhidraClass gc = (GhidraClass) resolved;

        String[] error = { null };
        try {
            ctx.runWrite("function set-class-association " + entry, () -> {
                try {
                    // Function.setParentNamespace returns void (the change is
                    // committed on the function in place). createClassStructIfNeeded
                    // fires automatically inside the call (on first edit / first
                    // association) to materialize a stub struct if none exists.
                    function.setParentNamespace(gc);
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
        return new FunctionSetClassAssociationResponse(
            function.getName(),
            gc.getName(true));
    }

    @Override
    public boolean mutates() {
        return true;
    }

    /**
     * Success response carrying the function's name and the class path it
     * was associated with.
     */
    static final class FunctionSetClassAssociationResponse extends RpcResponse {
        final String functionName;
        final String classPath;

        FunctionSetClassAssociationResponse(String functionName, String classPath) {
            this.success = true;
            this.functionName = functionName;
            this.classPath = classPath;
        }
    }

    /**
     * Check whether any data type in the program's DTM (across all
     * categories) has the given leaf name. Used by the
     * "no class namespace, but a struct of that name exists" hint —
     * the common mistake is conflating the DTM struct (which
     * describes layout) with the class namespace (which is the
     * symbol-table object the function gets associated with).
     * The two are coupled by name only.
     */
    private static boolean dtmHasTypeNamed(RpcContext ctx, String leafName) {
        java.util.Iterator<DataType> it =
            ctx.program().getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            if (leafName.equals(it.next().getName())) {
                return true;
            }
        }
        return false;
    }
}
