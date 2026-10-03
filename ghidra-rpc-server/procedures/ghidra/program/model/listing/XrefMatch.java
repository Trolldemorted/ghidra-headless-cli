package procedures.ghidra.program.model.listing;

/**
 * One matched reference in a xref response. Serialized by gson (null fields are
 * omitted, so a from-instruction with no containing function omits {@code
 * fromFunction}).
 */
final class XrefMatch {
    final String fromAddress;     // "0x401000" — the call site
    final String fromFunction;    // function containing the call site, or null
    /** Entry point of that function; null when fromFunction is null. Lets the
     *  client show the from-address as an offset inside it rather than implying
     *  the row sits at the function's entry. */
    final String fromFunctionEntry;
    final String refType;         // RefType.getName() — "CALL", "UNCONDITIONAL_CALL", "DATA", ...
    final int opIndex;            // operand index, or -1 for non-operand refs
    final boolean isExternal;     // target is in EXTERNAL space
    final boolean isOffcut;       // the reference's "from" doesn't start on an instruction boundary
    final boolean compositeMatch; // found via the containing data item, not the exact address
    /** Destination address this ref actually points at, when compositeMatch. */
    final String componentAddress;
    /** Name of the component that address falls in, or null. */
    final String componentField;


    XrefMatch(String fromAddress, String fromFunction, String refType,
            int opIndex, boolean isExternal, boolean isOffcut) {
        this(fromAddress, fromFunction, null, refType, opIndex, isExternal,
            isOffcut, false, null, null);
    }

    XrefMatch(String fromAddress, String fromFunction, String fromFunctionEntry,
            String refType, int opIndex, boolean isExternal, boolean isOffcut,
            boolean compositeMatch, String componentAddress, String componentField) {
        this.fromAddress = fromAddress;
        this.fromFunction = fromFunction;
        this.fromFunctionEntry = fromFunctionEntry;
        this.refType = refType;
        this.opIndex = opIndex;
        this.isExternal = isExternal;
        this.isOffcut = isOffcut;
        this.compositeMatch = compositeMatch;
        this.componentAddress = componentAddress;
        this.componentField = componentField;
    }

    boolean isCompositeMatch() {
        return compositeMatch;
    }
}
