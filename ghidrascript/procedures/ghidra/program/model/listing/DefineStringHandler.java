package procedures.ghidra.program.model.listing;

import java.util.Set;

import com.google.gson.JsonObject;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.PascalStringDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure DefineString: materialize a Defined String at {@code address}
 * using one of Ghidra's string DataType singletons. The kind string picks
 * which one (null-terminated, fixed-length, Pascal, UTF-8/16/32, ...).
 *
 * <p>For null-terminated and Pascal kinds Ghidra derives the string length
 * from the data (terminator byte or length prefix); we dispatch via
 * {@link CreateDataCmd}.
 *
 * <p>For fixed-length kinds ({@code string}, {@code utf8}, {@code unicode})
 * the caller MUST pass {@code length}; we call
 * {@link Listing#createData(Address, DataType, int)} directly inside a
 * transaction because {@code CreateDataCmd} has no length overload.
 *
 * <p>Mutating. Goes through {@link RpcContext#runWrite} so the transaction,
 * checkout and check-in happen via the standard path.
 */
public final class DefineStringHandler implements RpcProcedure {

    /** Fixed-length kinds that require an explicit {@code length}. */
    private static final Set<String> FIXED_LENGTH_KINDS =
        Set.of("string", "utf8", "unicode");

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String kindRaw = RpcContext.optStr(req, "kind");
        if (kindRaw == null || kindRaw.isEmpty()) {
            return RpcResponse.error(
                "Missing required field 'kind' (cstring, string, utf8, utf16, unicode, pascal, pascal255).");
        }
        String kind = kindRaw.toLowerCase();
        DataType dt = dataTypeFor(kind);
        if (dt == null) {
            return RpcResponse.error("Unknown kind '" + kindRaw
                + "': must be cstring, string, utf8, utf16, unicode, pascal, pascal255.");
        }

        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));

        boolean isFixed = FIXED_LENGTH_KINDS.contains(kind);
        int length = RpcContext.optInt(req, "length", -1);
        if (isFixed && length < 1) {
            return RpcResponse.error(
                "'length' is required for fixed-length kind '" + kind + "' (must be >= 1).");
        }

        // Run the mutation inside the standard transaction.
        Throwable[] error = { null };
        try {
            if (isFixed) {
                ctx.runWrite("define-string " + kind + "[" + length + "] @ " + addr, () -> {
                    try {
                        Listing listing = ctx.program().getListing();
                        listing.createData(addr, dt, length);
                    } catch (Exception e) {
                        error[0] = e;
                        throw new RuntimeException(e);
                    }
                });
            } else {
                Command<Program> cmd = new CreateDataCmd(addr, dt);
                RpcResponse applyError = ctx.applyCommand(cmd);
                if (applyError != null && !applyError.success) {
                    return applyError;
                }
            }
        } catch (RuntimeException re) {
            Throwable cause = re.getCause() != null ? re.getCause() : re;
            return RpcResponse.error("Cannot define string at " + addr + ": " + cause.getMessage());
        }
        if (error[0] != null) {
            return RpcResponse.error("Cannot define string at " + addr + ": " + error[0].getMessage());
        }

        // After creation the Data exists; read its charset from
        // StringDataInstance (the DataType's default charset).
        String charset = null;
        try {
            Data created = ctx.program().getListing().getDataAt(addr);
            if (created != null) {
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(created);
                if (sdi != null) charset = sdi.getCharsetName();
            }
        } catch (Exception ignored) {
            // best-effort; not all kinds yield a StringDataInstance pre-terminator
        }
        return new DefineStringResponse(addr.toString(), kind, length, charset);
    }

    private static DataType dataTypeFor(String kind) {
        switch (kind) {
            case "cstring":   return TerminatedStringDataType.dataType;
            case "string":    return StringDataType.dataType;
            case "utf8":      return StringUTF8DataType.dataType;
            case "utf16":     return TerminatedUnicodeDataType.dataType;
            case "unicode":   return UnicodeDataType.dataType;
            case "pascal":    return PascalStringDataType.dataType;
            case "pascal255": return PascalString255DataType.dataType;
            default:          return null;
        }
    }

    @Override
    public boolean mutates() {
        return true;
    }
}
