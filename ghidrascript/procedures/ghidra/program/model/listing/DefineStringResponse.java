package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/** Success response for DefineString. */
final class DefineStringResponse extends RpcResponse {
    final String address;
    final String kind;
    final int length;
    final String charset;

    DefineStringResponse(String address, String kind, int length, String charset) {
        this.success = true;
        this.address = address;
        this.kind = kind;
        this.length = length;
        this.charset = charset;
    }
}
