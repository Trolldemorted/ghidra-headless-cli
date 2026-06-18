package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/**
 * Success response for ReadBytes. {@code data} is a string whose shape depends
 * on the requested format: a space-separated hex string for {@code hex}, or
 * newline-separated rows for {@code dump}.
 */
final class ReadBytesResponse extends RpcResponse {
    final String address;
    final int length;         // requested length
    final int bytesRead;      // actual bytes read (< length if the range ran off a block)
    final String format;
    final String data;

    ReadBytesResponse(String address, int length, int bytesRead, String format, String data) {
        this.success = true;
        this.address = address;
        this.length = length;
        this.bytesRead = bytesRead;
        this.format = format;
        this.data = data;
    }
}
