package procedures.ghidra.program.model.listing;

/**
 * One imported symbol. Serialized by gson — null fields are omitted.
 */
final class ImportMatch {
    final String name;            // the imported label (e.g. "CreateFileW")
    final String address;         // the EXTERNAL-space address Ghidra assigned, e.g. "EXTERNAL:00000010"
    final String originalName;    // unmangled/original name when Ghidra records it, else null
    final String source;          // SourceType.getName() — "IMPORTED", "USER_DEFINED", "DEFAULT", ...
    final boolean isFunction;     // true => external function; false => external data

    ImportMatch(String name, String address, String originalName,
            String source, boolean isFunction) {
        this.name = name;
        this.address = address;
        this.originalName = originalName;
        this.source = source;
        this.isFunction = isFunction;
    }
}
