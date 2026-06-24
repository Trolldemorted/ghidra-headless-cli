package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
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
 * exactly the GUI's per-row content. Undefined bytes (gaps between defined
 * units, where memory IS initialized but no Instruction/Data has been
 * created) are emitted as {@code kind:"undefined"} rows so the output
 * mirrors what the GUI shows — gap rows in the Listing view, 16-byte rows
 * in the Hex view. Uninitialized memory (no MemoryBlock backing it, or a
 * block whose {@code isInitialized()} is false) yields no row at all —
 * matches the GUI, which shows nothing for uninitialized regions. Each
 * gap is split into {@link #UNDEFINED_CHUNK_BYTES}-byte chunks so a long
 * gap produces a grep-friendly sequence of short rows rather than one
 * 1024-byte line.
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
 *   <li>Undefined bytes → {@code kind="undefined"} with {@code address},
 *       {@code bytes?}, empty {@code label}/{@code mnemonic}/{@code type}/
 *       {@code representation}. 16 bytes per row max.</li>
 * </ul>
 *
 * <p>Read-only, like {@code Disassemble} and {@code FlatDecompilerAPI}:
 * {@link #mutates()} is false; the file is checked out per dispatch policy
 * but not checked in (no mutation).
 *
 * <p>The {@code "start"} / {@code "end"} fields echo the first and last
 * requested addresses (normalized) so callers can detect the case where
 * {@code count} is much smaller than {@code end-start+1} (i.e. the range
 * spans unmapped bytes). Empty range (no defined units, no readable
 * memory) yields {@code count: 0}, not an error.
 */
public final class ListingsHandler implements RpcProcedure {

    /** How often to check the monitor for cancellation while iterating. */
    private static final int CANCEL_CHECK_INTERVAL = 256;

    /** Maximum bytes per `undefined` row. Matches Ghidra's Hex view (16 bytes
     * per row) so the CLI dump mirrors the GUI's hex-pane layout. */
    private static final int UNDEFINED_CHUNK_BYTES = 16;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        AddressSetView addrSet = ctx.addressSet(req);
        boolean includeBytes = RpcContext.reqBool(req, "bytes");

        Listing listing = ctx.program().getListing();
        CodeUnitFormat fmt = CodeUnitFormat.DEFAULT;
        Memory memory = ctx.program().getMemory();

        // First/last address of the requested range, for the response envelope.
        // For AddressSetView.getFirstRange()/getLastRange() — both safe on the
        // empty set? Ghidra's AddressSetView returns null on empty; handle that.
        AddressRange firstRange = addrSet.getFirstRange();
        AddressRange lastRange = addrSet.getLastRange();
        String startAddr = firstRange != null ? firstRange.getMinAddress().toString() : null;
        String endAddr = lastRange != null ? lastRange.getMaxAddress().toString() : null;

        List<Unit> units = new ArrayList<>();
        int emitted = 0;

        // Walk the defined units in address order, emitting an undefined-row
        // gap between each pair (and around the head/tail of the requested
        // range). The cursor starts at the requested range's first address;
        // each iteration either emits a defined unit and advances the cursor
        // past it, or — when the cursor doesn't coincide with a unit — emits
        // one or more undefined rows up to the next unit (or the end of the
        // range). Because defined CodeUnits cannot overlap, the cursor is
        // monotonically increasing and we never re-emit a row.
        Address cursor = firstRange == null ? null : firstRange.getMinAddress();
        Address rangeEnd = lastRange == null ? null : lastRange.getMaxAddress();
        if (cursor != null) {
            for (CodeUnit cu : listing.getCodeUnits(addrSet, true)) {
                if ((emitted++ % CANCEL_CHECK_INTERVAL) == 0) {
                    ctx.monitor().checkCancelled();
                }
                Address unitStart = cu.getMinAddress();
                Address unitEnd = cu.getMaxAddress();
                // Cursor lives strictly before this unit — gap to emit.
                if (cursor.compareTo(unitStart) < 0) {
                    Address gapEnd = unitStart.previous();
                    emitted += emitUndefinedGap(memory, units, cursor, gapEnd,
                        includeBytes, ctx, emitted);
                }
                // Emit the defined unit itself.
                units.add(buildUnit(cu, includeBytes, fmt));
                // Advance cursor past the unit.
                cursor = unitEnd.next();
            }
            // Trailing gap (cursor up to and including rangeEnd).
            if (cursor != null && rangeEnd != null && cursor.compareTo(rangeEnd) <= 0) {
                emitted += emitUndefinedGap(memory, units, cursor, rangeEnd,
                    includeBytes, ctx, emitted);
            }
        }

        return new ListingsResponse(startAddr, endAddr, units.size(), units);
    }

    /** Build an Instruction or Data row from a defined code unit. */
    private static Unit buildUnit(CodeUnit cu, boolean includeBytes, CodeUnitFormat fmt) {
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
            return new Unit(
                "instruction",
                address,
                label,
                bytes,
                insn.getMnemonicString(),
                null, // no data type for instructions
                representation);
        }
        if (cu instanceof Data data) {
            return new Unit(
                "data",
                address,
                label,
                bytes,
                null, // no mnemonic for data
                data.getDataType().getName(),
                representation);
        }
        // Unknown CodeUnit subtype — skip. The user asked for "what the GUI
        // shows" which is exactly Instruction + Data + undefined; anything
        // else (shouldn't happen with stock Listing) is out of scope.
        return null;
    }

    /** Emit `kind:"undefined"` rows for the byte range [start, endInclusive].
     * Returns the number of rows added. The range is chunked into
     * {@link #UNDEFINED_CHUNK_BYTES}-byte rows so a long gap produces
     * grep-friendly short lines. Skips bytes that fail to read (uninitialized
     * memory — matches the GUI, which shows nothing for those regions). */
    private static int emitUndefinedGap(Memory memory, List<Unit> units,
            Address start, Address endInclusive, boolean includeBytes,
            RpcContext ctx, int emittedSoFar) throws Exception {
        int added = 0;
        Address cur = start;
        byte[] buf = new byte[UNDEFINED_CHUNK_BYTES];
        while (cur.compareTo(endInclusive) <= 0) {
            if ((emittedSoFar + added) % CANCEL_CHECK_INTERVAL == 0) {
                ctx.monitor().checkCancelled();
            }
            // Compute chunk end: either +15 or endInclusive, whichever comes first.
            Address chunkEnd;
            try {
                Address candidate = cur.addNoWrap(UNDEFINED_CHUNK_BYTES - 1);
                chunkEnd = candidate.compareTo(endInclusive) > 0 ? endInclusive : candidate;
            } catch (AddressOutOfBoundsException e) {
                // Near the top of the address space — just clamp to endInclusive.
                chunkEnd = endInclusive;
            }
            int chunkLen = (int) chunkEnd.subtract(cur) + 1;
            String bytes = null;
            if (includeBytes) {
                try {
                    // Memory.getBytes(Address, byte[], int, int) returns the
                    // number of bytes actually read into buf — buf is the
                    // destination, not the return value. Fill chunkLen bytes
                    // (or fewer at the tail of an uninitialized region, which
                    // throws below before we get here).
                    memory.getBytes(cur, buf, 0, chunkLen);
                    bytes = toHex(java.util.Arrays.copyOf(buf, chunkLen));
                } catch (MemoryAccessException e) {
                    // Uninitialized memory block — GUI shows nothing here; skip.
                    // Still advance past it; the caller doesn't want raw zeros.
                    cur = chunkEnd.next();
                    continue;
                }
            }
            // kind="undefined" row. No label, no mnemonic, no type, no
            // representation — these are all properties of defined units.
            units.add(new Unit(
                "undefined",
                cur.toString(),
                "",      // empty label (no symbol here)
                bytes,
                null,    // no mnemonic
                null,    // no data type
                ""));    // empty representation (no semantic content for undefined)
            added++;
            cur = chunkEnd.next();
        }
        return added;
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
        // matching the per-row content of the GUI Listings window. `undefined`
        // rows leave both null.
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
