package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/**
 * Success response for Callgraph in JSON format. Same envelope as
 * {@link CallgraphResponse} but emits the raw node/edge lists instead of a
 * Mermaid rendering, so the caller can drive its own visualization.
 */
final class CallgraphJsonResponse extends RpcResponse {
    final CallgraphNode root;
    final String direction;
    final int depth;
    final boolean truncated;
    final List<CallgraphNode> nodes;
    final List<CallgraphEdge> edges;

    CallgraphJsonResponse(CallgraphNode root, String direction, int depth,
            boolean truncated, List<CallgraphNode> nodes, List<CallgraphEdge> edges) {
        this.success = true;
        this.root = root;
        this.direction = direction;
        this.depth = depth;
        this.truncated = truncated;
        this.nodes = nodes;
        this.edges = edges;
    }
}
