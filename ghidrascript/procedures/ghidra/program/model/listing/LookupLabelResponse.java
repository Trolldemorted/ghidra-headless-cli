package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for LookupLabel. */
final class LookupLabelResponse extends RpcResponse {
    final int count;
    final List<LabelMatch> refs;

    LookupLabelResponse(int count, List<LabelMatch> refs) {
        this.success = true;
        this.count = count;
        this.refs = refs;
    }
}
