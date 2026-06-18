package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for the function-search procedures. */
final class FindFunctionsResponse extends RpcResponse {
    final int count;
    final boolean truncated; // true if a limit cut the result short
    final List<FunctionMatch> functions;

    FindFunctionsResponse(int count, boolean truncated, List<FunctionMatch> functions) {
        this.success = true;
        this.count = count;
        this.truncated = truncated;
        this.functions = functions;
    }
}
