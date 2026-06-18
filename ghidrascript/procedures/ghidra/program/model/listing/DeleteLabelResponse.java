package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/** Success response for DeleteLabel. */
final class DeleteLabelResponse extends RpcResponse {
    final boolean deleted;
    final String name;
    final String address;

    DeleteLabelResponse(boolean deleted, String name, String address) {
        this.success = true;
        this.deleted = deleted;
        this.name = name;
        this.address = address;
    }
}
