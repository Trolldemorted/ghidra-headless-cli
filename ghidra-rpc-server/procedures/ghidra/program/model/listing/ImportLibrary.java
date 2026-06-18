package procedures.ghidra.program.model.listing;

import java.util.List;

/**
 * One external library and the imports that came from it. Mirrors how the
 * Ghidra Imports window groups rows under their parent library node.
 */
final class ImportLibrary {
    final String name;             // e.g. "KERNEL32.dll"
    final int count;
    final List<ImportMatch> entries;

    ImportLibrary(String name, int count, List<ImportMatch> entries) {
        this.name = name;
        this.count = count;
        this.entries = entries;
    }
}
