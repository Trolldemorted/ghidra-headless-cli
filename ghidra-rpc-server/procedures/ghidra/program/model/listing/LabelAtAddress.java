package procedures.ghidra.program.model.listing;

/** One label at an address. Used by GetLabel. */
final class LabelAtAddress {
    final String name;
    final boolean isPrimary;
    /** Slash path of the label's namespace; omitted for the global namespace. */
    final String namespace;

    LabelAtAddress(String name, boolean isPrimary, String namespace) {
        this.namespace = namespace;
        this.name = name;
        this.isPrimary = isPrimary;
    }
}
