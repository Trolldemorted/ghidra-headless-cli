package procedures.ghidra.program.model.listing;

/**
 * One label (non-function symbol) entry. Serialized by gson; null fields omitted.
 *
 * <p>Used by {@link ListLabelsHandler} and {@link LookupLabelHandler}.
 */
final class LabelMatch {
    final String name;            // the label, e.g. "g_tick"
    final String address;         // e.g. "00401000" (or "EXTERNAL:..." for imports — see LookupLabel)
    final String source;          // SourceType.toString() — "USER_DEFINED", "IMPORTED", ...
    final String symbolType;      // SymbolType.toString() — "Label", "Function", ... (lookup only)
    final boolean isExternal;     // lookup only
    final boolean isPrimary;      // lookup only

    LabelMatch(String name, String address, String source) {
        this(name, address, source, null, false, false);
    }

    LabelMatch(String name, String address, String source, String symbolType,
            boolean isExternal, boolean isPrimary) {
        this.name = name;
        this.address = address;
        this.source = source;
        this.symbolType = symbolType;
        this.isExternal = isExternal;
        this.isPrimary = isPrimary;
    }
}
