package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/** Success response for CreateLabel. */
final class CreateLabelResponse extends RpcResponse {
    final String name;
    final String address;
    final String source;
    /** Slash path of the label's namespace; omitted for the global namespace. */
    final String namespace;

    CreateLabelResponse(String name, String address, String source) {
        this(name, address, source, null);
    }

    CreateLabelResponse(String name, String address, String source, String namespace) {
        this.success = true;
        this.namespace = namespace;
        this.name = name;
        this.address = address;
        this.source = source;
    }
}
