package procedures.ghidra.program.model.listing;

import java.util.List;

import procedures.RpcResponse;

/**
 * Success response for GetLabel: the address (echo), the primary label name at
 * that address (or null if unlabeled), and ALL labels (primary + secondary) at
 * the address.
 */
final class GetLabelResponse extends RpcResponse {
    final String address;
    final String primary;             // null if no primary label
    final List<LabelAtAddress> all;

    GetLabelResponse(String address, String primary, List<LabelAtAddress> all) {
        this.success = true;
        this.address = address;
        this.primary = primary;
        this.all = all;
    }
}
