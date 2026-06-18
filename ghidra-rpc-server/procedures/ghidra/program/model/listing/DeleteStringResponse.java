package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/**
 * Success response for {@link DeleteStringHandler}. Echoes back the address,
 * the DataType name that was removed, and the byte length that was cleared,
 * so the caller can confirm the right unit was removed.
 */
final class DeleteStringResponse extends RpcResponse {
    final String address;
    final String dataType;
    final int length;

    DeleteStringResponse(String address, String dataType, int length) {
        this.success = true;
        this.address = address;
        this.dataType = dataType;
        this.length = length;
    }
}
