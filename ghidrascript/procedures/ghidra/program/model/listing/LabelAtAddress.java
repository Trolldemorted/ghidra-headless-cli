package procedures.ghidra.program.model.listing;

/** One label at an address. Used by GetLabel. */
final class LabelAtAddress {
    final String name;
    final boolean isPrimary;

    LabelAtAddress(String name, boolean isPrimary) {
        this.name = name;
        this.isPrimary = isPrimary;
    }
}
