package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Procedure Listings: dump the Listing-window view for an address range.
 *
 * <p>Mirrors {@link DisassembleHandler} but lifts the function-body scope: the
 * caller supplies an arbitrary {@code addressSet:[{start,end?}]} or single
 * {@code address} (resolved via {@link RpcContext#addressSet}), and the handler
 * yields every code unit the GUI's Listings window would render in that range.
 *
 * <p>{@link Listing#getCodeUnits(AddressSetView, boolean)} returns
 * {@link Instruction}s, defined {@link Data} and one single-byte undefined
 * {@link Data} per remaining memory byte, in address order. Runs of undefined
 * bytes are folded into {@code kind:"undefined"} rows of up to
 * {@link #UNDEFINED_CHUNK_BYTES} bytes (the Hex view's row width) so a long
 * run is a short sequence of rows rather than one row per byte. A run is cut
 * at every labelled byte, so no label is hidden inside a row. Addresses with
 * no memory block yield nothing, and neither do unlabelled undefined bytes in
 * an uninitialized block (there is nothing to show for them).
 *
 * <p>A range that starts in the middle of a unit shows that unit (for a
 * struct/union: its components that reach into the range), like the GUI does
 * when you navigate into the middle of one.
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
 *       No mnemonic — Data doesn't have one. If the data's type is a composite
 *       (Struct/Union), one row per immediate component is appended with
 *       {@code kind="data"} and {@code depth >= 1}; components that are
 *       themselves composite recurse, producing the GUI's "expanded" view of
 *       vftables and structs (the GUI shows each field on its own indented
 *       line). The parent's bytes are clamped to the requested range so a
 *       struct whose body extends past the range doesn't dump hundreds of
 *       bytes the caller didn't ask for.</li>
 *   <li>Undefined bytes → {@code kind="undefined"} with {@code address},
 *       {@code label} (empty unless the first byte is labelled),
 *       {@code bytes?}, and an empty {@code representation}. 16 bytes per row
 *       max.</li>
 * </ul>
 *
 * <p>Read-only, like {@code Disassemble} and {@code FlatDecompilerAPI}:
 * {@link #mutates()} is false; the file is checked out per dispatch policy
 * but not checked in (no mutation).
 *
 * <p>The {@code "start"} / {@code "end"} fields echo the first and last
 * requested addresses (normalized). A range with no memory behind it yields
 * {@code count: 0}, not an error.
 */
public final class ListingsHandler implements RpcProcedure {

    /** How often to check the monitor for cancellation while iterating. */
    private static final int CANCEL_CHECK_INTERVAL = 256;

    /** Maximum bytes per `undefined` row. Matches Ghidra's Hex view (16 bytes
     * per row) so the CLI dump mirrors the GUI's hex-pane layout. */
    private static final int UNDEFINED_CHUNK_BYTES = 16;

    /** Cap on recursion depth when expanding composite Data units. A struct
     * nested inside a struct nested inside a struct ... would otherwise be
     * infinite (self-referential pointer types) or arbitrarily deep. The GUI
     * shows 1–3 levels in practice; 8 is plenty headroom and bounds worst-case
     * output size. */
    private static final int MAX_COMPOSITE_DEPTH = 8;

    /** Most addresses one request may cover, summed over its ranges (1 MiB). */
    private static final long MAX_ADDRESSES = 0x100000;

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

        // Bound the work: this read-only call needs no write password and
        // runs under the server-wide lock.
        if (addrSet.getNumAddresses() > MAX_ADDRESSES) {
            return RpcResponse.error("Listing range too large: " + addrSet.getNumAddresses()
                + " addresses requested, at most " + MAX_ADDRESSES
                + " per request. Request a smaller range.");
        }

        Walk walk = new Walk(listing, memory, fmt, includeBytes, ctx);
        // Each requested range is walked on its own, so nothing between two
        // ranges leaks into the output.
        for (AddressRange range : addrSet) {
            walk.range(new AddressSet(range));
        }
        return new ListingsResponse(startAddr, endAddr, walk.units.size(), walk.units);
    }

    /** State of one request's walk over the listing. */
    private final class Walk {
        final Listing listing;
        final Memory memory;
        final CodeUnitFormat fmt;
        final boolean includeBytes;
        final RpcContext ctx;
        final List<Unit> units = new ArrayList<>();

        // Pending run of undefined bytes, not yet emitted.
        private Address runStart;
        private Address runEnd;
        private String runLabel;
        private int steps;

        Walk(Listing listing, Memory memory, CodeUnitFormat fmt, boolean includeBytes,
                RpcContext ctx) {
            this.listing = listing;
            this.memory = memory;
            this.fmt = fmt;
            this.includeBytes = includeBytes;
            this.ctx = ctx;
        }

        void range(AddressSetView range) throws Exception {
            Address rangeStart = range.getMinAddress();
            Address rangeEnd = range.getMaxAddress();
            // getCodeUnits only yields units that START inside the range. A
            // unit that starts before it and reaches into it is shown too:
            // a struct/union as its visible components (no parent row, the
            // parent is "scrolled off" above), anything else as its own row.
            CodeUnit head = listing.getCodeUnitContaining(rangeStart);
            if (head != null && head.getMinAddress().compareTo(rangeStart) < 0) {
                if (head instanceof Data parent && parent.getDataType() instanceof Composite) {
                    expandComponents(parent, includeBytes, fmt, memory, units, 1, range,
                        rangeEnd, ctx, units.size());
                } else {
                    emitDataUnit(head, includeBytes, fmt, memory, units, 0, range, rangeEnd,
                        ctx, units.size());
                }
            }
            for (CodeUnit cu : listing.getCodeUnits(range, true)) {
                if ((steps++ % CANCEL_CHECK_INTERVAL) == 0) {
                    ctx.monitor().checkCancelled();
                }
                if (cu instanceof Data data && !data.isDefined()) {
                    undefined(cu);
                    continue;
                }
                flush();
                // The parent's bytes are clamped to the requested range (a
                // struct whose body extends past the end shouldn't dump
                // bytes the caller didn't ask for).
                emitDataUnit(cu, includeBytes, fmt, memory, units, 0, range, rangeEnd, ctx,
                    units.size());
            }
            flush();
        }

        /** Add one undefined byte to the pending run, starting a new run when
         * it is labelled, not adjacent, or the run is full. */
        private void undefined(CodeUnit cu) {
            Address a = cu.getMinAddress();
            String label = cu.getLabel();
            boolean extend = runStart != null && label == null
                && runEnd.isSuccessor(a)
                && runEnd.subtract(runStart) + 1 < UNDEFINED_CHUNK_BYTES;
            if (extend) {
                runEnd = a;
                return;
            }
            flush();
            runStart = a;
            runEnd = a;
            runLabel = label == null ? "" : label;
        }

        /** Emit the pending run of undefined bytes as one row. */
        private void flush() {
            if (runStart == null) {
                return;
            }
            Address start = runStart;
            int len = (int) runEnd.subtract(runStart) + 1;
            runStart = null;
            MemoryBlock block = memory.getBlock(start);
            boolean initialized = block != null && block.isInitialized();
            if (!initialized && runLabel.isEmpty()) {
                return; // nothing to show for bare uninitialized bytes
            }
            String bytes = null;
            if (includeBytes && initialized) {
                try {
                    byte[] buf = new byte[len];
                    int got = memory.getBytes(start, buf, 0, len);
                    bytes = toHex(java.util.Arrays.copyOf(buf, Math.max(got, 0)));
                } catch (MemoryAccessException e) {
                    bytes = null;
                }
            }
            units.add(new Unit("undefined", start.toString(), runLabel, bytes,
                null,    // no mnemonic
                null,    // no data type
                "",      // no semantic content for undefined bytes
                0));     // never nested under a composite
        }
    }

    /** Walk the components of a composite Data unit, emitting one row per
     * component that overlaps the requested range, recursively for nested
     * composites. Returns the number of rows added. {@code depth} is the
     * depth of the emitted component rows (depth of the components
     * themselves, NOT of the parent — caller controls this). */
    private int expandComponents(Data parent, boolean includeBytes, CodeUnitFormat fmt,
            Memory memory, List<Unit> units, int depth, AddressSetView range,
            Address rangeEnd, RpcContext ctx, int emittedSoFar) throws Exception {
        if (depth > MAX_COMPOSITE_DEPTH) {
            return 0;
        }
        int added = 0;
        Address rangeMin = range.getMinAddress();
        Address rangeMax = range.getMaxAddress();
        int n = parent.getNumComponents();
        for (int i = 0; i < n; i++) {
            if ((emittedSoFar + added) % CANCEL_CHECK_INTERVAL == 0) {
                ctx.monitor().checkCancelled();
            }
            Data comp = parent.getComponent(i);
            if (comp == null || comp.getLength() <= 0) {
                continue;
            }
            // Component overlaps the requested range if its [min, max]
            // intersects [rangeMin, rangeMax]. Two cases:
            //   - comp.max < rangeMin : entirely before our range, skip
            //   - comp.min > rangeMax : entirely after our range, skip
            // Otherwise the component overlaps (or is contained in) the
            // range — emit it.
            if (comp.getMaxAddress().compareTo(rangeMin) < 0) {
                continue;
            }
            if (comp.getMinAddress().compareTo(rangeMax) > 0) {
                continue;
            }
            // Emit the component row. Component bytes are clamped to the
            // requested range (a 4-byte field whose 3rd byte is past
            // rangeMax gets a 2-byte bytes string — matches what the GUI
            // shows for a partially-visible field).
            Unit row = buildUnit(comp, includeBytes, fmt, memory, depth,
                includeBytes ? clampEnd(comp, rangeEnd) : null);
            if (row != null) {
                units.add(row);
                added++;
                // Recurse if this component is itself a composite — expand
                // its sub-components one level deeper.
                if (comp.getDataType() instanceof Composite) {
                    added += expandComponents(comp, includeBytes, fmt, memory, units,
                        depth + 1, range, rangeEnd, ctx, emittedSoFar + added);
                }
            }
        }
        return added;
    }

    /** Emit a single defined code unit (Instruction or Data), and — if it's a
     * composite Data — one row per immediate component, recursively. Returns
     * the number of rows added. {@code depth} is 0 for a top-level unit
     * (yielded by {@link Listing#getCodeUnits}) and increases by 1 per
     * recursion level into a composite. {@code rangeEnd} caps the parent's
     * bytes to the caller's requested range; component bytes get their own
     * clamp via {@link #expandComponents}.
     *
     * <p>Component rows are emitted via {@link #expandComponents}, which
     * also handles the partial-parent case (range starts in the middle of
     * a composite: called with the parent absent and depth=1).
     */
    private int emitDataUnit(CodeUnit cu, boolean includeBytes, CodeUnitFormat fmt,
            Memory memory, List<Unit> units, int depth, AddressSetView range, Address rangeEnd,
            RpcContext ctx, int emittedSoFar) throws Exception {
        Unit parent = buildUnit(cu, includeBytes, fmt, memory, depth,
            includeBytes ? clampEnd(cu, rangeEnd) : null);
        if (parent == null) {
            return 0;
        }
        units.add(parent);
        int added = 1;

        // Composite expansion: only Struct/Union get the per-field rows.
        // Arrays (`int[10]`, `char[14]`) are kept as a single row — matches
        // the GUI's default rendering, and avoids 1000-row dumps for large
        // arrays.
        if (!(cu instanceof Data data) || !(data.getDataType() instanceof Composite)) {
            return added;
        }
        added += expandComponents(data, includeBytes, fmt, memory, units,
            depth + 1, range, rangeEnd, ctx, emittedSoFar + added);
        return added;
    }

    /** For a top-level Data unit, the bytes string should not extend past
     * the caller's requested end address — a struct whose body is larger
     * than the window would otherwise dump hundreds of bytes the caller
     * didn't ask for. Returns the clamped end address for the unit, or
     * null if no clamp is needed (unit already fits, or no rangeEnd). */
    private static Address clampEnd(CodeUnit cu, Address rangeEnd) {
        if (rangeEnd == null) {
            return null;
        }
        Address unitEnd = cu.getMaxAddress();
        if (unitEnd.compareTo(rangeEnd) <= 0) {
            return null; // unit fits in range, no clamp needed
        }
        return rangeEnd;
    }

    /** Build an Instruction or Data row from a defined code unit. {@code depth}
     * is included in the row; {@code clampEnd}, if non-null, limits the read
     * to {@code [cu.min, clampEnd]} so the bytes string doesn't extend past
     * the caller's requested range. For component rows ({@code depth >= 1}),
     * the label is the struct/union field name — not the parent's label,
     * which would be misleading when the first component shares the parent's
     * starting address (e.g. vftable's first entry inherits the vftable's
     * own {@code g_pXxx_vftable} label). */
    private static Unit buildUnit(CodeUnit cu, boolean includeBytes, CodeUnitFormat fmt,
            Memory memory, int depth, Address clampEnd) {
        String address = cu.getMinAddress().toString();
        String label;
        if (cu instanceof Data data && depth >= 1) {
            // Component row — prefer the field name from the parent
            // composite. `getFieldName()` returns the empty string for
            // unnamed fields (e.g. anonymous union members), in which case
            // we fall back to the address's label (rarely set on a field).
            label = data.getFieldName();
            if (label == null || label.isEmpty()) {
                label = cu.getLabel();
            }
        } else {
            label = cu.getLabel();
        }
        String bytes = null;
        if (includeBytes) {
            try {
                if (clampEnd != null) {
                    int len = (int) clampEnd.subtract(cu.getMinAddress()) + 1;
                    byte[] buf = new byte[len];
                    int got = memory.getBytes(cu.getMinAddress(), buf, 0, len);
                    if (got > 0) {
                        bytes = toHex(java.util.Arrays.copyOf(buf, got));
                    }
                } else {
                    bytes = toHex(cu.getBytes());
                }
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
                representation,
                depth);
        }
        if (cu instanceof Data data) {
            return new Unit(
                "data",
                address,
                label,
                bytes,
                null, // no mnemonic for data
                data.getDataType().getName(),
                representation,
                depth);
        }
        // Unknown CodeUnit subtype — skip. The user asked for "what the GUI
        // shows" which is exactly Instruction + Data + undefined; anything
        // else (shouldn't happen with stock Listing) is out of scope.
        return null;
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
        // Indentation depth: 0 for top-level rows (yielded by
        // Listing.getCodeUnits), >=1 for components of a composite Data unit
        // (struct/union). The CLI renders nested rows with `2 * depth`
        // leading spaces, mirroring the GUI's expanded-listing indentation.
        // Always present (gson defaults to 0) — top-level rows have depth=0.
        final int depth;

        Unit(String kind, String address, String label, String bytes,
                String mnemonic, String type, String representation, int depth) {
            this.kind = kind;
            this.address = address;
            this.label = label;
            this.bytes = bytes;
            this.mnemonic = mnemonic;
            this.type = type;
            this.representation = representation;
            this.depth = depth;
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
