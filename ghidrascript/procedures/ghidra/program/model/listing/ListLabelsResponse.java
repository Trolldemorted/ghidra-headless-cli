package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for ListLabels. */
final class ListLabelsResponse extends RpcResponse {
    final int count;
    final boolean truncated;
    final List<LabelMatch> refs;

    ListLabelsResponse(int count, boolean truncated, List<LabelMatch> refs) {
        this.success = true;
        this.count = count;
        this.truncated = truncated;
        this.refs = refs;
    }
}
