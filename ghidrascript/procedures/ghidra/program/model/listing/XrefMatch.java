package procedures.ghidra.program.model.listing;

/**
 * One matched reference in a xref response. Serialized by gson (null fields are
 * omitted, so a from-instruction with no containing function omits {@code
 * fromFunction}).
 */
final class XrefMatch {
    final String fromAddress;     // "0x401000" — the call site
    final String fromFunction;    // function containing the call site, or null
    final String refType;         // RefType.getName() — "CALL", "UNCONDITIONAL_CALL", "DATA", ...
    final int opIndex;            // operand index, or -1 for non-operand refs
    final boolean isExternal;     // target is in EXTERNAL space
    final boolean isOffcut;       // the reference's "from" doesn't start on an instruction boundary

    XrefMatch(String fromAddress, String fromFunction, String refType,
            int opIndex, boolean isExternal, boolean isOffcut) {
        this.fromAddress = fromAddress;
        this.fromFunction = fromFunction;
        this.refType = refType;
        this.opIndex = opIndex;
        this.isExternal = isExternal;
        this.isOffcut = isOffcut;
    }
}
