package procedures.ghidra.program.model.listing;

import procedures.RpcResponse;

/**
 * Success response for GetString. {@code string} is null when the address is
 * not a defined string; otherwise it carries the same per-string fields
 * that {@link DefinedStringListResponse} uses for each entry of a search
 * result (value / representation / length / charset / dataType).
 */
final class GetStringResponse extends RpcResponse {
    final String address;
    final DefinedStringMatch string;     // null when no defined string at address

    GetStringResponse(String address, DefinedStringMatch string) {
        this.success = true;
        this.address = address;
        this.string = string;
    }
}
