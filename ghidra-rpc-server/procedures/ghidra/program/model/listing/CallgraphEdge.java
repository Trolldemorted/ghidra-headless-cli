package procedures.ghidra.program.model.listing;

/**
 * One edge in a callgraph. {@code from} / {@code to} are function names
 * (matching {@link CallgraphNode#name}); {@code refType} is the Ghidra
 * {@code RefType.getName()} string ("UNCONDITIONAL_CALL", "CALL", "DATA",
 * "JUMP", etc.) so the caller can distinguish calls from non-call refs.
 */
final class CallgraphEdge {
    final String from;
    final String to;
    final int depth;
    final String refType;

    CallgraphEdge(String from, String to, int depth, String refType) {
        this.from = from;
        this.to = to;
        this.depth = depth;
        this.refType = refType;
    }
}
