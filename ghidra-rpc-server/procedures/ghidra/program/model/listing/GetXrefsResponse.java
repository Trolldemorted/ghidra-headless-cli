package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for GetXrefs: target resolved + list of incoming references. */
final class GetXrefsResponse extends RpcResponse {
    final XrefTarget target;
    final int count;
    final boolean truncated;
    final List<XrefMatch> refs;

    GetXrefsResponse(XrefTarget target, int count, boolean truncated, List<XrefMatch> refs) {
        this.success = true;
        this.target = target;
        this.count = count;
        this.truncated = truncated;
        this.refs = refs;
    }
}
