package procedures.ghidra.program.model.listing;

/**
 * One edge in a callgraph. {@code from} / {@code to} are function names
 * (matching {@link CallgraphNode#name}); {@code refType} is the Ghidra
 * {@code RefType.getName()} string ("UNCONDITIONAL_CALL", "CALL", "DATA",
 * "JUMP", etc.) so the caller can distinguish calls from non-call refs.
 * {@code fromAddress} / {@code toAddress} match {@link CallgraphNode#address}
 * and identify the two nodes exactly: names are not unique (overloads, the
 * same name in two namespaces).
 */
final class CallgraphEdge {
    final String from;
    final String to;
    final String fromAddress;
    final String toAddress;
    final int depth;
    final String refType;

    CallgraphEdge(CallgraphNode from, CallgraphNode to, int depth, String refType) {
        this.from = from.name;
        this.to = to.name;
        this.fromAddress = from.address;
        this.toAddress = to.address;
        this.depth = depth;
        this.refType = refType;
    }
}
