package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/** Success response for GetImports: libraries grouped, with their entries. */
final class GetImportsResponse extends RpcResponse {
    final int count;                          // total imports across all libraries
    final int libraryCount;                   // distinct external libraries
    final boolean truncated;
    final List<ImportLibrary> libraries;

    GetImportsResponse(int count, int libraryCount, boolean truncated, List<ImportLibrary> libraries) {
        this.success = true;
        this.count = count;
        this.libraryCount = libraryCount;
        this.truncated = truncated;
        this.libraries = libraries;
    }
}
