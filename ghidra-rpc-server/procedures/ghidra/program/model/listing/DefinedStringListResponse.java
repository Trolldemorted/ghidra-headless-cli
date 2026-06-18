package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for FindStrings / ListDefinedStrings. */
final class DefinedStringListResponse extends RpcResponse {
    final int count;
    final boolean truncated;
    final List<DefinedStringMatch> strings;

    DefinedStringListResponse(int count, boolean truncated, List<DefinedStringMatch> strings) {
        this.success = true;
        this.count = count;
        this.truncated = truncated;
        this.strings = strings;
    }
}
