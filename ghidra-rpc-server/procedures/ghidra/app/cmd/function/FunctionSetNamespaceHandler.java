package procedures.ghidra.app.cmd.function;

import com.google.gson.JsonObject;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

/**
 * Procedure FunctionSetNamespace: move a function into a (possibly different)
 * namespace and rename it. Both edits are applied atomically inside one
 * transaction so a partial failure rolls back cleanly.
 *
 * <p>Request: {@code { file, address, namespace?, name, source? }}.
 * {@code address} is the function's entry-point address.
 * {@code namespace} is a slash-delimited project path (e.g.
 * {@code "/Game/MultiplayerScreen"}); {@code "/"}, empty, or absent means the
 * program's global namespace. {@code name} is the new BARE LEAF name
 * (must not contain {@code "::"} or {@code "/"}).
 *
 * <p>Unlike {@code function set-name}, which rejects {@code "::"} because
 * Ghidra's underlying rename silently mangles such inputs (see
 * {@code SetFunctionNameCmdHandler}), this verb IS the explicit move path.
 * It accepts plain {@link Namespace}s (not just {@code GhidraClass}) — for
 * the class-only variant with auto-stub semantics, use
 * {@code function set-class-association} instead.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class FunctionSetNamespaceHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address entry = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Function function = ctx.requireFunctionAt(entry);

        String rawNs = RpcContext.optStr(req, "namespace");
        String leaf = RpcContext.reqStr(req, "name");

        // Bare-leaf check: a name containing "::" or "/" is either a path
        // (handled by --namespace) or, if passed to Ghidra directly, would
        // be silently mangled. Reject up front to match the SetFunctionNameCmd
        // guard and keep the CLI's intent unambiguous.
        if (leaf.contains("::") || leaf.contains("/")) {
            return RpcResponse.error(
                "--name must be a bare leaf (no '::' or '/'). "
                + "Got '" + leaf + "'. "
                + "Pass the namespace path via --namespace instead.");
        }

        Namespace target;
        try {
            target = NamespaceResolve.resolve(ctx, rawNs);
        } catch (Exception e) {
            return RpcResponse.error(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }

        String[] error = { null };
        try {
            ctx.runWrite("function set-namespace " + entry, () -> {
                try {
                    // setParentNamespace accepts plain Namespace AND GhidraClass
                    // (it accepts the common base type). The CLI's separate
                    // set-class-association variant restricts to GhidraClass so
                    // the auto-stub contract is enforced; this verb leaves the
                    // target type to the caller.
                    function.setParentNamespace(target);
                    function.setName(leaf, ctx.sourceType(RpcContext.optStr(req, "source")));
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
        return new FunctionSetNamespaceResponse(
            function.getName(),
            slashPath(target));
    }

    /** Render a namespace's full path as {@code "/Foo/Bar"} (matches --class syntax). */
    private static String slashPath(Namespace ns) {
        if (ns.getParentNamespace() == null) {
            return "/";
        }
        java.util.List<String> segs = new java.util.ArrayList<>();
        for (Namespace n = ns; n != null && n.getParentNamespace() != null; n = n.getParentNamespace()) {
            segs.add(0, n.getName());
        }
        StringBuilder sb = new StringBuilder();
        for (String s : segs) {
            sb.append('/').append(s);
        }
        return sb.toString();
    }

    /**
     * Success response carrying the function's resulting name and the
     * slash-delimited namespace path it was placed in.
     */
    static final class FunctionSetNamespaceResponse extends RpcResponse {
        final String functionName;
        final String namespacePath;

        FunctionSetNamespaceResponse(String functionName, String namespacePath) {
            this.success = true;
            this.functionName = functionName;
            this.namespacePath = namespacePath;
        }
    }
}
