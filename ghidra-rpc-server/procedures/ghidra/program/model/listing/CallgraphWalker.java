package procedures.ghidra.program.model.listing;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import procedures.RpcContext;

/**
 * BFS walk of a function's call graph up to a depth limit, producing
 * {@link CallgraphNode}/{@callgraphEdge} records. Mirrors the traversal
 * approach in ghidrecomp's {@code get_calling_funcs_memo} /
 * {@code get_called_funcs_memo} (ghidrecomp/callgraph.py:538-612) but uses
 * BFS instead of DFS so that the Mermaid emitter can rely on parents
 * always appearing before children.
 *
 * <p>{@code direction="called"} walks references FROM each function body
 * and resolves the target as a callee (via {@link FunctionManager#getFunctionAt}).
 * {@code direction="calling"} walks references TO each function entry point
 * and resolves the source's containing function as a caller.
 *
 * <p>Cycles: when a neighbor function is already at the same or shallower
 * depth, the edge is still emitted (so the cycle is visible in the
 * output) but the function is not re-enqueued. External functions are
 * emitted as leaf nodes but never recursed into.
 */
final class CallgraphWalker {

    static final class Result {
        final List<CallgraphNode> nodes;
        final List<CallgraphEdge> edges;
        final boolean truncated;
        Result(List<CallgraphNode> nodes, List<CallgraphEdge> edges, boolean truncated) {
            this.nodes = nodes;
            this.edges = edges;
            this.truncated = truncated;
        }
    }

    private final RpcContext ctx;
    private final ReferenceManager rm;
    private final FunctionManager fm;
    private final String direction;
    private final int maxDepth;
    private final boolean includeRefs;
    private final int maxEdges;
    /** Node of every function seen so far (edges refer to nodes, not names). */
    private final Map<Function, CallgraphNode> nodeOf = new HashMap<>();
    /** Edges already emitted: one per (from, to, refType), however many call sites. */
    private final Set<String> edgeKeys = new HashSet<>();

    CallgraphWalker(RpcContext ctx, ReferenceManager rm, FunctionManager fm,
            String direction, int maxDepth, boolean includeRefs, int maxEdges) {
        this.ctx = ctx;
        this.rm = rm;
        this.fm = fm;
        this.direction = direction;
        this.maxDepth = maxDepth;
        this.includeRefs = includeRefs;
        this.maxEdges = maxEdges;
    }

    Result walk(Function root) {
        List<CallgraphNode> nodes = new ArrayList<>();
        List<CallgraphEdge> edges = new ArrayList<>();
        boolean[] truncated = { false };

        // Function -> recorded depth. Used both to skip re-enqueueing (cycle
        // detection) and to look up a node's depth when emitting an edge.
        Map<Function, Integer> visited = new HashMap<>();
        Deque<Function> queue = new ArrayDeque<>();
        nodeOf.clear();
        edgeKeys.clear();

        visited.put(root, 0);
        queue.add(root);
        nodes.add(makeNode(root, 0));

        while (!queue.isEmpty()) {
            if (ctx.monitor().isCancelled()) {
                truncated[0] = true;
                break;
            }
            Function current = queue.poll();
            int depth = visited.get(current);
            if (depth >= maxDepth) {
                continue; // leaf as far as the BFS is concerned
            }
            int nextDepth = depth + 1;

            if (direction.equals("called")) {
                walkCalled(current, depth, nextDepth, visited, queue, nodes, edges, truncated);
            } else {
                walkCalling(current, depth, nextDepth, visited, queue, nodes, edges, truncated);
            }
            if (truncated[0]) {
                break;
            }
        }
        return new Result(nodes, edges, truncated[0]);
    }

    private void walkCalled(Function from, int depth, int nextDepth,
            Map<Function, Integer> visited, Deque<Function> queue,
            List<CallgraphNode> nodes, List<CallgraphEdge> edges, boolean[] truncated) {

        AddressRangeIterator ranges = from.getBody().getAddressRanges();
        while (ranges.hasNext() && !truncated[0]) {
            if (ctx.monitor().isCancelled()) {
                truncated[0] = true;
                break;
            }
            AddressRange range = ranges.next();
            ReferenceIterator it = rm.getReferenceIterator(range.getMinAddress());
            while (it.hasNext()) {
                Reference ref = it.next();
                // The reference iterator walks program order; stop once we
                // leave the current body chunk.
                if (!range.contains(ref.getFromAddress())) {
                    break;
                }
                if (!includeRefs && !ref.getReferenceType().isCall()) {
                    continue;
                }
                Function callee = fm.getFunctionAt(ref.getToAddress());
                boolean isExternalCall = callee == null && ref.isExternalReference();
                if (callee == null && !isExternalCall) {
                    // Data reference / non-call jump to a non-function:
                    // only interesting when the caller asked for it.
                    if (!includeRefs) {
                        continue;
                    }
                    // Even with includeRefs, if there's no function to name
                    // on the other end and it's not external, skip the
                    // unresolvable ref.
                    continue;
                }
                if (callee == null) {
                    // External call: record as a leaf node keyed by its
                    // referenced symbol name, not a function object.
                    String extName = ref.getReferenceType().isCall()
                        ? externalSymbolName(ref.getToAddress())
                        : null;
                    if (extName == null) {
                        continue;
                    }
                    CallgraphNode leaf = addLeaf(nodes, extName, ref.getToAddress().toString(),
                        nextDepth, true);
                    if (appendEdge(edges, truncated, nodeOf.get(from), leaf,
                            nextDepth, ref.getReferenceType().getName())) {
                        return;
                    }
                    continue;
                }
                if (visited.containsKey(callee)) {
                    // Cycle: emit the edge so the cycle is visible, but
                    // don't re-enqueue.
                    if (appendEdge(edges, truncated, nodeOf.get(from), nodeOf.get(callee),
                            nextDepth, ref.getReferenceType().getName())) {
                        return;
                    }
                    continue;
                }
                visited.put(callee, nextDepth);
                nodes.add(makeNode(callee, nextDepth));
                if (nextDepth < maxDepth) {
                    queue.add(callee);
                }
                if (appendEdge(edges, truncated, nodeOf.get(from), nodeOf.get(callee),
                        nextDepth, ref.getReferenceType().getName())) {
                    return;
                }
            }
        }
    }

    private void walkCalling(Function to, int depth, int nextDepth,
            Map<Function, Integer> visited, Deque<Function> queue,
            List<CallgraphNode> nodes, List<CallgraphEdge> edges, boolean[] truncated) {

        ReferenceIterator it = rm.getReferencesTo(to.getEntryPoint());
        while (it.hasNext()) {
            if (ctx.monitor().isCancelled()) {
                truncated[0] = true;
                break;
            }
            Reference ref = it.next();
            if (!includeRefs && !ref.getReferenceType().isCall()) {
                continue;
            }
            Function caller = fm.getFunctionContaining(ref.getFromAddress());
            if (caller == null) {
                continue;
            }
            if (visited.containsKey(caller)) {
                if (appendEdge(edges, truncated, nodeOf.get(caller), nodeOf.get(to),
                        nextDepth, ref.getReferenceType().getName())) {
                    return;
                }
                continue;
            }
            visited.put(caller, nextDepth);
            nodes.add(makeNode(caller, nextDepth));
            if (nextDepth < maxDepth) {
                queue.add(caller);
            }
            if (appendEdge(edges, truncated, nodeOf.get(caller), nodeOf.get(to),
                        nextDepth, ref.getReferenceType().getName())) {
                return;
            }
        }
    }

    /**
     * Add the edge unless the same (from, to, refType) was already emitted:
     * a function that calls another from ten call sites is one edge of the
     * graph, and ten copies used to eat the edge cap.
     *
     * @return true when the edge cap is hit (signals the caller to stop).
     */
    private boolean appendEdge(List<CallgraphEdge> edges, boolean[] truncated,
            CallgraphNode from, CallgraphNode to, int depth, String refType) {
        if (!edgeKeys.add(from.address + ">" + to.address + ">" + refType)) {
            return false;
        }
        edges.add(new CallgraphEdge(from, to, depth, refType));
        if (edges.size() >= maxEdges) {
            truncated[0] = true;
            return true;
        }
        return false;
    }

    private CallgraphNode makeNode(Function f, int depth) {
        CallgraphNode n = new CallgraphNode(f.getName(), f.getEntryPoint().toString(), depth,
            f.isExternal());
        nodeOf.put(f, n);
        return n;
    }

    /**
     * Record an external leaf by its (synthesized) name + EXTERNAL address.
     * External functions aren't Function objects, so we can't use the
     * Function-keyed {@code visited} map; we name-de-duplicate instead.
     */
    private CallgraphNode addLeaf(List<CallgraphNode> nodes, String name, String address,
            int depth, boolean isExternal) {
        for (CallgraphNode n : nodes) {
            if (n.isExternal && n.name.equals(name)) {
                return n;
            }
        }
        CallgraphNode n = new CallgraphNode(name, address, depth, isExternal);
        nodes.add(n);
        return n;
    }

    /**
     * Best-effort external symbol name lookup. The reference's destination
     * in EXTERNAL space doesn't itself carry a symbol — we look it up via
     * the symbol table; if nothing's there we fall back to a derived name
     * like {@code EXTERNAL:0010f000}.
     */
    private String externalSymbolName(Address extAddr) {
        var sym = fm.getProgram().getSymbolTable().getPrimarySymbol(extAddr);
        if (sym != null) {
            return sym.getName(true);
        }
        return "EXTERNAL:" + extAddr.toString();
    }
}
