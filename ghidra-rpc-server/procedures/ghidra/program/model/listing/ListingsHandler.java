package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Procedure Listings: dump the Listing-window view for an address range.
 *
 * <p>Mirrors {@link DisassembleHandler} but lifts the function-body scope: the
 * caller supplies an arbitrary {@code addressSet:[{start,end?}]} or single
 * {@code address} (resolved via {@link RpcContext#addressSet}), and the handler
 * yields every code unit the GUI's Listings window would render in that range.
 *
 * <p>{@link Listing#getCodeUnits(AddressSetView, boolean)} returns BOTH
 * {@link Instruction} and {@link Data} units in address order, which is
 * exactly the GUI's per-row content. Undefined bytes (gaps with no listing
 * entry) are skipped — the user opted out of those (full GUI fidelity would
 * also surface unmapped gaps and comments; out of scope for v1).
 *
 * <p>Each unit is dispatched by type:
 * <ul>
 *   <li>{@link Instruction} → {@code kind="instruction"} with
 *       {@code address}, {@code label}, {@code bytes?}, {@code mnemonic},
 *       {@code representation} (the latter via {@link CodeUnitFormat#DEFAULT},
 *       the same call {@link DisassembleHandler} uses — resolves operand
 *       references the way the GUI does, e.g. {@code CALL FUN_004100b0}).</li>
 *   <li>{@link Data} → {@code kind="data"} with {@code address}, {@code label},
 *       {@code bytes?}, {@code type} (the data type name, e.g. {@code "char[14]"}),
 *       {@code representation} (rendered value, e.g. {@code "\"Hello, world!\""}).
 *       No mnemonic — Data doesn't have one.</li>
 * </ul>
 *
 * <p>Read-only, like {@code Disassemble} and {@code FlatDecompilerAPI}:
 * {@link #mutates()} is false; the file is checked out per dispatch policy
 * but not checked in (no mutation).
 *
 * <p>The {@code "start"} / {@code "end"} fields echo the first and last
 * requested addresses (normalized) so callers can detect the case where
 * {@code count} is much smaller than {@code end-start+1} (i.e. the range
 * spans unmapped bytes). Empty range (no defined units) yields
 * {@code count: 0}, not an error.
 */
public final class ListingsHandler implements RpcProcedure {

    /** How often to check the monitor for cancellation while iterating. */
    private static final int CANCEL_CHECK_INTERVAL = 256;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        AddressSetView addrSet = ctx.addressSet(req);
        boolean includeBytes = RpcContext.optBool(req, "bytes", true);

        Listing listing = ctx.program().getListing();
        CodeUnitFormat fmt = CodeUnitFormat.DEFAULT;

        // First/last address of the requested range, for the response envelope.
        // For AddressSetView.getFirstRange()/getLastRange() — both safe on the
        // empty set? Ghidra's AddressSetView returns null on empty; handle that.
        AddressRange firstRange = addrSet.getFirstRange();
        AddressRange lastRange = addrSet.getLastRange();
        String startAddr = firstRange != null ? firstRange.getMinAddress().toString() : null;
        String endAddr = lastRange != null ? lastRange.getMaxAddress().toString() : null;

        List<Unit> units = new ArrayList<>();
        int emitted = 0;
        for (CodeUnit cu : listing.getCodeUnits(addrSet, true)) {
            if ((emitted++ % CANCEL_CHECK_INTERVAL) == 0) {
                ctx.monitor().checkCancelled();
            }
            String address = cu.getMinAddress().toString();
            String label = cu.getLabel();
            String bytes = null;
            if (includeBytes) {
                try {
                    bytes = toHex(cu.getBytes());
                } catch (MemoryAccessException e) {
                    bytes = null; // uninitialized memory: omit bytes for this line
                }
            }
            String representation = fmt.getRepresentationString(cu);
            if (cu instanceof Instruction insn) {
                units.add(new Unit(
                    "instruction",
                    address,
                    label,
                    bytes,
                    insn.getMnemonicString(),
                    null, // no data type for instructions
                    representation));
            }
            else if (cu instanceof Data data) {
                units.add(new Unit(
                    "data",
                    address,
                    label,
                    bytes,
                    null, // no mnemonic for data
                    data.getDataType().getName(),
                    representation));
            }
            // Unknown CodeUnit subtype (shouldn't happen with stock Listing):
            // skip silently. The user asked for "what the GUI shows" which is
            // exactly Instruction + Data.
        }

        return new ListingsResponse(startAddr, endAddr, units.size(), units);
    }

    /** Listings does not change the program, so no check-in is required. */
    @Override
    public boolean mutates() {
        return false;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    /** One listing row; serialized by gson (null fields omitted). */
    static final class Unit {
        final String kind;
        final String address;
        final String label;
        final String bytes;
        // Exactly one of `mnemonic` (instruction) and `type` (data) is set,
        // matching the per-row content of the GUI Listings window.
        final String mnemonic;
        final String type;
        final String representation;

        Unit(String kind, String address, String label, String bytes,
                String mnemonic, String type, String representation) {
            this.kind = kind;
            this.address = address;
            this.label = label;
            this.bytes = bytes;
            this.mnemonic = mnemonic;
            this.type = type;
            this.representation = representation;
        }
    }

    /** Success response carrying the range's listing-window content. */
    static final class ListingsResponse extends RpcResponse {
        final String start;
        final String end;
        final int count;
        final List<Unit> units;

        ListingsResponse(String start, String end, int count, List<Unit> units) {
            this.success = true;
            this.start = start;
            this.end = end;
            this.count = count;
            this.units = units;
        }
    }
}
