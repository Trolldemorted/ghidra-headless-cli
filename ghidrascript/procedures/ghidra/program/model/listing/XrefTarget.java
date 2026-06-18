package procedures.ghidra.program.model.listing;

/**
 * The resolved xref target: which kind of lookup ran and what address the
 * server settled on. Carrying the resolved address back lets the caller see
 * "you asked for function 'printf' → I found it at 0x401234" without having
 * to re-query.
 */
final class XrefTarget {
    final String type;     // "function" | "symbol" | "address"
    final String query;    // what the caller asked for
    final String address;  // resolved Address.toString()

    XrefTarget(String type, String query, String address) {
        this.type = type;
        this.query = query;
        this.address = address;
    }
}
