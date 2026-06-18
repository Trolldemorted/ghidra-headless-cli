package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for GetExports: list of in-program entry points. */
final class GetExportsResponse extends RpcResponse {
    final int count;
    final boolean truncated;
    final List<ExportMatch> refs;

    GetExportsResponse(int count, boolean truncated, List<ExportMatch> refs) {
        this.success = true;
        this.count = count;
        this.truncated = truncated;
        this.refs = refs;
    }
}
