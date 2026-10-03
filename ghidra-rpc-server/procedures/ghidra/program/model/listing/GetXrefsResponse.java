package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for GetXrefs: target resolved + list of incoming references. */
final class GetXrefsResponse extends RpcResponse {
    final XrefTarget target;
    final int count;
    final boolean truncated;
    /**
     * Name of the data type of the composite data item covering the target, or
     * null when the target is not inside one. Non-null means the reference
     * list may include compositeMatch entries — references landing on a
     * component of this item rather than on the target address itself.
     */
    final String containingDataType;
    final List<XrefMatch> refs;

    GetXrefsResponse(XrefTarget target, int count, boolean truncated,
            String containingDataType, List<XrefMatch> refs) {
        this.success = true;
        this.target = target;
        this.count = count;
        this.truncated = truncated;
        this.containingDataType = containingDataType;
        this.refs = refs;
    }
}
