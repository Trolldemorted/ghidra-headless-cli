package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure ReadBytes: read up to {@code length} bytes starting at {@code
 * address} and return them as hex.
 *
 * <p>Two formats:
 * <ul>
 *   <li>{@code hex} (default) — single space-separated string of
 *       {@code "a3 8f 1c …"} bytes.
 *   <li>{@code dump} — multi-row {@code hexdump -C}-style output with 16 bytes
 *       per row, an 8/8 half-row split, and an ASCII column on the right.
 * </ul>
 *
 * <p>{@code length} is capped at {@value #MAX_LENGTH} bytes per call. The
 * actual byte count returned may be less than the requested length if the
 * range runs off the end of a memory block; the {@code bytesRead} field
 * reports the true count.
 *
 * <p>Read-only.
 */
public final class ReadBytesHandler implements RpcProcedure {

    /** Maximum bytes per request — keep the ndjson response line bounded. */
    static final int MAX_LENGTH = 65536;

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        int length = RpcContext.optInt(req, "length", 0);
        if (length < 1 || length > MAX_LENGTH) {
            return RpcResponse.error("Length must be 1.." + MAX_LENGTH + ".");
        }
        String formatRaw = RpcContext.optStr(req, "format");
        String format = (formatRaw == null || formatRaw.isEmpty()) ? "hex" : formatRaw.toLowerCase();
        if (!format.equals("hex") && !format.equals("dump")) {
            return RpcResponse.error("Invalid 'format' '" + format + "': must be hex or dump.");
        }

        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        Memory mem = ctx.program().getMemory();
        if (!mem.contains(addr)) {
            return RpcResponse.error("Address not in any memory block: " + addr);
        }

        byte[] buf = new byte[length];
        int n;
        try {
            n = mem.getBytes(addr, buf);
        } catch (MemoryAccessException e) {
            return RpcResponse.error("Unreadable at " + addr + ": " + e.getMessage());
        }

        String data = format.equals("hex") ? toHexLine(buf, n) : toHexDump(buf, n, addr.toString());
        return new ReadBytesResponse(addr.toString(), length, n, format, data);
    }

    @Override
    public boolean mutates() {
        return false;
    }

    /** Hex string of {@code n} bytes, space-separated, e.g. {@code "a3 8f 1c"}. */
    private static String toHexLine(byte[] data, int n) {
        StringBuilder sb = new StringBuilder(n * 3);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(' ');
            int b = data[i] & 0xff;
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    /**
     * {@code hexdump -C}-style output: 16 bytes per row, 8-byte half-rows with
     * a 2-space gutter, ASCII column on the right.
     */
    private static String toHexDump(byte[] data, int n, String baseAddr) {
        StringBuilder sb = new StringBuilder(n * 4);
        for (int row = 0; row < n; row += 16) {
            int end = Math.min(row + 16, n);
            sb.append(baseAddr);
            sb.append("  ");
            for (int col = row; col < end; col++) {
                int b = data[col] & 0xff;
                if (col == row + 8) sb.append("  ");
                else if (col > row) sb.append(' ');
                sb.append(Character.forDigit((b >> 4) & 0xf, 16));
                sb.append(Character.forDigit(b & 0xf, 16));
            }
            // Pad a short last row so the ASCII column lines up.
            if (end - row < 16) {
                int shortBytes = 16 - (end - row);
                int padSpaces = shortBytes * 3 + (shortBytes > 8 ? -1 : 0);
                for (int p = 0; p < padSpaces; p++) sb.append(' ');
            }
            sb.append("  |");
            for (int col = row; col < end; col++) {
                int b = data[col] & 0xff;
                char c = (b >= 0x20 && b < 0x7f) ? (char) b : '.';
                sb.append(c);
            }
            sb.append('|');
            if (end < n) sb.append('\n');
        }
        return sb.toString();
    }
}
