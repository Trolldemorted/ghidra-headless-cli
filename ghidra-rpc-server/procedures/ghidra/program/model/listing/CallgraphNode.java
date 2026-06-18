package procedures.ghidra.program.model.listing;

/**
 * One node in a callgraph. {@code address} is the function's entry-point
 * address (or the EXTERNAL-space stub address for external functions);
 * {@code depth} is the BFS layer from the root (0 = the root itself);
 * {@code isExternal} marks functions that live in EXTERNAL space (not
 * recursed into when walking).
 */
final class CallgraphNode {
    final String name;
    final String address;
    final int depth;
    final boolean isExternal;

    CallgraphNode(String name, String address, int depth, boolean isExternal) {
        this.name = name;
        this.address = address;
        this.depth = depth;
        this.isExternal = isExternal;
    }
}
