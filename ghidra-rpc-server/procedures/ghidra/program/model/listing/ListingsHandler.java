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
import ghidra.program.model.data.Composite;
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
 *       No mnemonic — Data doesn't have one. If the data's type is a composite
 *       (Struct/Union), one row per immediate component is appended with
 *       {@code kind="data"} and {@code depth >= 1}; components that are
 *       themselves composite recurse, producing the GUI's "expanded" view of
 *       vftables and structs (the GUI shows each field on its own indented
 *       line). The parent's bytes are clamped to the requested range so a
 *       struct whose body extends past the range doesn't dump hundreds of
 *       bytes the caller didn't ask for.</li>
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

    /** Cap on recursion depth when expanding composite Data units. A struct
     * nested inside a struct nested inside a struct ... would otherwise be
     * infinite (self-referential pointer types) or arbitrarily deep. The GUI
     * shows 1–3 levels in practice; 8 is plenty headroom and bounds worst-case
     * output size. */
    private static final int MAX_COMPOSITE_DEPTH = 8;

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
        //
        // For composite Data units (Struct/Union) we additionally emit one
        // row per immediate component, indented by `depth >= 1`, so the CLI
        // dump matches the GUI's "expanded" listing view. Components that are
        // themselves composite recurse. The cursor still advances past the
        // PARENT's max address — component rows are emitted at addresses
        // INSIDE the parent, but we don't want to re-walk them as separate
        // top-level units (they're not separate CodeUnits at the Listing
        // level). Array components are NOT expanded (the GUI shows
        // `int[10]`/`char[14]` as one row with a value-summary, not as ten
        // primitive rows); only Struct and Union get the component expansion.
        Address cursor = firstRange == null ? null : firstRange.getMinAddress();
        Address rangeEnd = lastRange == null ? null : lastRange.getMaxAddress();
        if (cursor != null) {
            // Partial-parent handling: if the requested range starts in the
            // MIDDLE of a composite Data unit (parent's min address is
            // before the range, but its body extends into the range), the
            // main getCodeUnits loop below won't include it — the parent
            // isn't in the result. The GUI still shows the parent's
            // visible components. Detect that case via getCodeUnitBefore
            // and emit the visible components at depth=1 (no parent row,
            // since the parent itself is outside the requested range).
            // The returned address (if non-null) is where the cursor
            // should advance to so the trailing gap doesn't re-emit
            // addresses already covered by the partial-parent components.
            Address partialEnd = emitPartialParentComponents(
                listing, memory, units, cursor, addrSet, rangeEnd,
                includeBytes, fmt, ctx, emitted);
            if (partialEnd != null) {
                cursor = partialEnd;
            }
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
                // Emit the defined unit itself. The parent's bytes are
                // clamped to the requested range (a struct whose body
                // extends past the endAddr shouldn't dump bytes the caller
                // didn't ask for); non-Data units and component rows are
                // emitted as-is.
                int parentRows = emitDataUnit(cu, includeBytes, fmt, memory, units, 0, addrSet, rangeEnd, ctx, emitted);
                emitted += parentRows;
                // Advance cursor past the parent (covers the parent's body
                // AND all its components — the parent's max address is the
                // bound of the whole struct).
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

    /** When the requested range starts in the MIDDLE of a composite Data unit,
     * emit the parent's visible components as rows at depth=1, recursing for
     * nested composites. No parent row — the parent's start address is
     * outside the requested range, so the GUI's Listing view also has no
     * parent header to show (the parent is just "scrolled off" above the
     * visible range).
     *
     * <p>Returns the address the cursor should advance to after the partial
     * expansion — specifically {@code parent.getMaxAddress().next()} — so
     * the main loop's trailing gap doesn't re-emit addresses already
     * covered by partial-parent components. Returns {@code null} when no
     * expansion happened (no preceding composite parent, or the parent's
     * body doesn't overlap the range).
     *
     * <p>Only fires when the code unit immediately preceding the range is a
     * composite Data unit whose body overlaps the range start; otherwise this
     * is a no-op.
     */
    private Address emitPartialParentComponents(Listing listing, Memory memory, List<Unit> units,
            Address rangeStart, AddressSetView range, Address rangeEnd,
            boolean includeBytes, CodeUnitFormat fmt, RpcContext ctx, int emittedSoFar)
            throws Exception {
        CodeUnit preceding = listing.getCodeUnitBefore(rangeStart);
        if (!(preceding instanceof Data parent)) {
            return null;
        }
        if (parent.getMaxAddress().compareTo(rangeStart) < 0) {
            return null; // parent ends before our range; no overlap
        }
        if (!(parent.getDataType() instanceof Composite)) {
            return null; // arrays / primitives / typedefs — no per-component rows
        }
        // Parent overlaps and is composite — walk its components. For each
        // component, emit it at depth=1 if any part of its address range
        // overlaps the requested range (NOT just minAddress — a component
        // that starts before the range but extends into it is still shown
        // by the GUI; e.g. a `CDrawable_vftable base` sub-struct that
        // contains scalarDtor at parent+0 and getClassName at parent+4
        // shows getClassName when the range starts at parent+2).
        expandComponents(parent, includeBytes, fmt, memory, units,
            1, range, rangeEnd, ctx, emittedSoFar);
        // Cursor advance: the main loop must skip the parent's entire body
        // (all addresses within [parent.min, parent.max]) so it doesn't
        // emit them as undefined gaps. parent.max+1 is correct regardless
        // of where the range ends.
        return parent.getMaxAddress().next();
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
     * a composite — called from {@link #emitPartialParentComponents}
     * with the parent absent and depth=1).
     */
    private int emitDataUnit(CodeUnit cu, boolean includeBytes, CodeUnitFormat fmt,
            Memory memory, List<Unit> units, int depth, AddressSetView range, Address rangeEnd,
            RpcContext ctx, int emittedSoFar) throws Exception {
        Unit parent = buildUnit(cu, includeBytes, fmt, memory, depth, includeBytes ? clampEnd(cu, rangeEnd) : null);
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
        }
        else {
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
                }
                else {
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
                "",      // empty representation (no semantic content for undefined)
                0));     // top-level (not nested under any composite)
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
