package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/**
 * Success response for Callgraph in Mermaid format. Carries the resolved
 * root, the request's direction/depth, truncation flag, and the Mermaid
 * `flowchart` source. Node/edge counts are not stored here — callers
 * that need them can derive them from the {@code mermaid} string (count
 * the node definitions and {@code -->} lines) or by switching to
 * {@code format=json} and reading {@code nodes[]} / {@code edges[]}.
 */
final class CallgraphResponse extends RpcResponse {
    final CallgraphNode root;
    final String direction;
    final int depth;
    final boolean truncated;
    final String mermaid;

    CallgraphResponse(CallgraphNode root, String direction, int depth,
            boolean truncated, String mermaid) {
        this.success = true;
        this.root = root;
        this.direction = direction;
        this.depth = depth;
        this.truncated = truncated;
        this.mermaid = mermaid;
    }
}
