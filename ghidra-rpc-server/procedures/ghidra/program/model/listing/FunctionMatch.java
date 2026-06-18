package procedures.ghidra.program.model.listing;

import java.util.List;

/**
 * One matched function in a function-search response; serialized by gson (a null
 * {@code tags} is omitted, so name searches don't carry the field).
 */
final class FunctionMatch {
    final String name;
    final String address;
    final List<String> tags; // the function's tags; populated by tag search, null otherwise

    FunctionMatch(String name, String address, List<String> tags) {
        this.name = name;
        this.address = address;
        this.tags = tags;
    }
}
