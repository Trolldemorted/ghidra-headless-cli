package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure Callgraph: walk a function's callers or callees to a depth and
 * return either a Mermaid {@code flowchart} string (default) or a
 * structured nodes/edges JSON envelope. Read-only; no checkout/check-in
 * required.
 *
 * <p>Request:
 * <pre>
 *   { "function": "&lt;name|address&gt;",
 *     "direction": "called|calling",   // default: called
 *     "depth": 1..10,                  // default: 2
 *     "format": "mermaid|json",        // default: mermaid
 *     "includeRefs": true|false }      // default: false
 * </pre>
 *
 * <p>The {@code function} field accepts a function name (exact match
 * against the function table, like {@code xrefs --type function}) or a hex
 * address. The response always echoes the resolved function name + entry
 * address so the caller can verify what was hit.
 *
 * <p>The BFS walker caps the total edge count at {@link #MAX_EDGES};
 * once the cap is hit, further expansion stops and the response sets
 * {@code truncated=true}.
 */
public final class CallgraphHandler implements RpcProcedure {

    /** Hard cap on the number of edges returned per call. */
    private static final int MAX_EDGES = 5000;
    /** Sanity ceiling for the depth parameter. */
    private static final int MAX_DEPTH_CAP = 10;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String fnSpec = RpcContext.reqStr(req, "function");
        if (fnSpec.isEmpty()) {
            return RpcResponse.error("Missing 'function'.");
        }
        String direction = RpcContext.reqStr(req, "direction");
        if (!"called".equals(direction) && !"calling".equals(direction)) {
            return RpcResponse.error(
                "Invalid 'direction' '" + direction + "': must be called or calling.");
        }
        int depth = RpcContext.reqInt(req, "depth");
        if (depth < 1 || depth > MAX_DEPTH_CAP) {
            return RpcResponse.error(
                "'depth' must be between 1 and " + MAX_DEPTH_CAP + ".");
        }
        String format = RpcContext.reqStr(req, "format");
        if (!"mermaid".equals(format) && !"json".equals(format)) {
            return RpcResponse.error(
                "Invalid 'format' '" + format + "': must be mermaid or json.");
        }
        boolean includeRefs = RpcContext.reqBool(req, "includeRefs");

        Function root = resolveFunction(ctx, fnSpec);
        if (root == null) {
            return RpcResponse.error("No function matched '" + fnSpec + "'.");
        }

        CallgraphWalker walker = new CallgraphWalker(
            ctx,
            ctx.program().getReferenceManager(),
            ctx.program().getFunctionManager(),
            direction, depth, includeRefs, MAX_EDGES);
        CallgraphWalker.Result result = walker.walk(root);

        CallgraphNode rootNode = new CallgraphNode(
            root.getName(), root.getEntryPoint().toString(), 0, root.isExternal());

        if ("mermaid".equals(format)) {
            String mermaid = CallgraphMermaid.render(result.nodes, result.edges, direction);
            return new CallgraphResponse(rootNode, direction, depth, result.truncated, mermaid);
        }
        return new CallgraphJsonResponse(rootNode, direction, depth,
            result.truncated, result.nodes, result.edges);
    }

    /** Read-only. */
    @Override
    public boolean mutates() {
        return false;
    }

    /**
     * Resolve a function spec: try as an address first, then exact name
     * match against the function table (case-sensitive). Mirrors
     * {@code GetXrefsHandler.resolveTarget} — first match wins and the
     * response always carries the resolved name+address so the caller
     * can detect collisions.
     */
    private static Function resolveFunction(RpcContext ctx, String spec) {
        FunctionManager fm = ctx.program().getFunctionManager();
        Address a = ctx.parseAddress(spec);
        if (a != null) {
            Function f = fm.getFunctionAt(a);
            if (f != null) {
                return f;
            }
        }
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(spec)) {
                return f;
            }
        }
        return null;
    }
}
