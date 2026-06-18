package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/** Success response for CreateLabel. */
final class CreateLabelResponse extends RpcResponse {
    final String name;
    final String address;
    final String source;

    CreateLabelResponse(String name, String address, String source) {
        this.success = true;
        this.name = name;
        this.address = address;
        this.source = source;
    }
}
