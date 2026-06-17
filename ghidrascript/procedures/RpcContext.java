package procedures;

import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.task.TaskMonitor;

/**
 * Per-server shared context + helper layer handed to every procedure.
 *
 * SYNCHRONIZATION: a single {@link #lock} (ReentrantLock) serializes the ENTIRE
 * lifecycle of every request — checkout, the procedure's program mutation, and the
 * check-in — because Ghidra's program database is not safe for concurrent mutation.
 * {@link #dispatch} holds the lock from before {@code execute} until after check-in,
 * so a procedure's mutation and its push are atomic with respect to other clients; no
 * other client can interleave a read or write in between. The lock is reentrant so a
 * procedure may call {@link #runWrite}/{@link #applyCommand} (which open program
 * transactions) without deadlock. Program transactions
 * ({@code startTransaction}/{@code endTransaction}) are a separate Ghidra-level
 * mechanism but are always opened while holding {@link #lock}.
 */
public class RpcContext {

    private final Program program;
    private final TaskMonitor monitor;

    /** Serializes all program access (see class doc). Reentrant for nested runWrite. */
    private final ReentrantLock lock = new ReentrantLock();

    public RpcContext(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    public Program program() {
        return program;
    }

    public TaskMonitor monitor() {
        return monitor;
    }

    // ---------------------------------------------------------------------------
    // Dispatch: checkout -> execute -> (if mutating) checkin, all under one lock.
    // ---------------------------------------------------------------------------

    /**
     * Run a procedure with exclusive program access. Holds {@link #lock} across the
     * whole sequence so checkout, mutation and check-in cannot interleave with other
     * clients. Per policy: every procedure checks the file out first; every successful
     * mutating procedure is checked in immediately and the call fails if the push fails.
     */
    public RpcResponse dispatch(RpcProcedure procedure, JsonObject request) throws Exception {
        lock.lock();
        try {
            RpcResponse checkoutError = ensureCheckout();
            if (checkoutError != null) {
                return checkoutError;
            }
            RpcResponse response = procedure.execute(request, this);
            if (response != null && response.success && procedure.mutates()) {
                RpcResponse checkinError = checkin(procedureOf(request));
                if (checkinError != null) {
                    return checkinError; // push failed -> the whole call fails
                }
            }
            return response;
        } finally {
            lock.unlock();
        }
    }

    private static String procedureOf(JsonObject request) {
        try {
            return request.get("procedure").getAsString();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /** Ensure the file is checked out before any procedure runs. Idempotent. */
    private RpcResponse ensureCheckout() {
        DomainFile df = program.getDomainFile();
        if (!df.isVersioned() || df.isCheckedOut()) {
            return null; // non-versioned local file, or already checked out: nothing to do
        }
        if (df.isReadOnly()) {
            return RpcResponse.error(
                "Read-only session; cannot check out. Launch the server in commit mode.");
        }
        try {
            if (!df.checkout(true, monitor)) { // exclusive checkout
                return RpcResponse.error("Failed to check out (already held by another user?).");
            }
            return null;
        } catch (Exception e) {
            return RpcResponse.error("Checkout failed: " + message(e));
        }
    }

    /**
     * Save + check the file in to the shared server so the change is immediately
     * visible to other clients. Returns null on success (or nothing to push) and an
     * error response if the push fails (per policy the whole call then fails).
     */
    private RpcResponse checkin(String procedure) {
        program.flushEvents();
        DomainFile df = program.getDomainFile();
        if (df.isReadOnly()) {
            return RpcResponse.error("Program is read-only; launch the server in commit mode.");
        }
        boolean changed = program.isChanged();
        try {
            if (changed && df.canSave()) {
                df.save(monitor);
            }
            if (!df.isVersioned()) {
                return null; // local non-versioned project: the save is the persistence
            }
            if (!df.isCheckedOut()) {
                return RpcResponse.error("File is not checked out; cannot check in.");
            }
            // modifiedSinceCheckout() can read false right after a save in a transient
            // headless checkout, so also honor isChanged() captured pre-save + canCheckin().
            if (changed || df.canCheckin() || df.modifiedSinceCheckout()) {
                // keepCheckedOut=true: the long-running server keeps editing; createKeepFile=false.
                df.checkin(new DefaultCheckinHandler(
                    "RPC " + procedure, true, false), monitor);
            }
            return null;
        } catch (Exception e) {
            return RpcResponse.error("Check-in/push failed: " + message(e));
        }
    }

    private static String message(Throwable t) {
        String m = t.getMessage();
        return (m != null && !m.isEmpty()) ? m : t.getClass().getSimpleName();
    }

    // ---------------------------------------------------------------------------
    // Command execution helpers
    // ---------------------------------------------------------------------------

    /** A unit of program mutation that may throw. */
    public interface Write {
        void run() throws Exception;
    }

    /**
     * Run {@code body} inside a program transaction (committed iff it returns
     * normally; otherwise rolled back and rethrown). Always called while holding
     * {@link #lock}.
     */
    public void runWrite(String description, Write body) throws Exception {
        int txId = program.startTransaction(description);
        boolean committed = false;
        try {
            body.run();
            committed = true;
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    /**
     * Apply a Ghidra {@link Command} to the program inside a transaction and map the
     * result to a response. Background commands get the real monitor.
     */
    public RpcResponse applyCommand(Command<Program> cmd) throws Exception {
        boolean[] ok = {false};
        runWrite(cmd.getName(), () -> {
            if (cmd instanceof BackgroundCommand) {
                @SuppressWarnings("unchecked")
                BackgroundCommand<Program> bg = (BackgroundCommand<Program>) cmd;
                ok[0] = bg.applyTo(program, monitor);
            } else {
                ok[0] = cmd.applyTo(program);
            }
        });
        if (!ok[0]) {
            String s = cmd.getStatusMsg();
            return RpcResponse.error((s != null && !s.isEmpty()) ? s : (cmd.getName() + " failed."));
        }
        return RpcResponse.ok();
    }

    // ---------------------------------------------------------------------------
    // Resolvers (throw IllegalArgumentException -> turned into error responses)
    // ---------------------------------------------------------------------------

    /** Parse {@code "0x401000"}, {@code "401000"} or {@code "ram:401000"}; null if invalid. */
    public Address parseAddress(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        Address a = tryAddress(t);
        if (a == null && (t.startsWith("0x") || t.startsWith("0X"))) {
            a = tryAddress(t.substring(2));
        }
        return a;
    }

    private Address tryAddress(String s) {
        try {
            return program.getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    public Address requireAddress(String s) {
        Address a = parseAddress(s);
        if (a == null) {
            throw new IllegalArgumentException("Invalid or missing address: " + s);
        }
        return a;
    }

    /**
     * Build an address set from either {@code "addressSet":[{start,end?},...]} or a
     * single {@code "address"}. Throws if neither is present.
     */
    public AddressSetView addressSet(JsonObject req) {
        if (req.has("addressSet") && req.get("addressSet").isJsonArray()) {
            AddressSet set = new AddressSet();
            for (JsonElement e : req.getAsJsonArray("addressSet")) {
                JsonObject o = e.getAsJsonObject();
                Address start = requireAddress(o.get("start").getAsString());
                Address end = o.has("end") ? requireAddress(o.get("end").getAsString()) : start;
                set.addRange(start, end);
            }
            return set;
        }
        if (req.has("address")) {
            return new AddressSet(requireAddress(req.get("address").getAsString()));
        }
        throw new IllegalArgumentException("Missing 'address' or 'addressSet'.");
    }

    public Function requireFunctionAt(Address entry) {
        Function f = program.getFunctionManager().getFunctionAt(entry);
        if (f == null) {
            throw new IllegalArgumentException("No function at " + entry + ".");
        }
        return f;
    }

    public Function requireFunctionAt(String address) {
        return requireFunctionAt(requireAddress(address));
    }

    /** Resolve a data type by name/expression (e.g. "int", "char *", "MyStruct[4]"). */
    public DataType dataType(String name) throws Exception {
        if (name == null || name.trim().isEmpty()) {
            return null;
        }
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL).parse(name);
        if (dt == null) {
            throw new IllegalArgumentException("Unknown data type: " + name);
        }
        return dt;
    }

    public DataType requireDataType(String name) throws Exception {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required data type.");
        }
        return dataType(name);
    }

    public Register requireRegister(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Missing required register.");
        }
        Register r = program.getRegister(name.trim());
        if (r == null) {
            throw new IllegalArgumentException("Unknown register: " + name);
        }
        return r;
    }

    /** Find a parameter or local variable of {@code function} by name. */
    public Variable requireVariable(Function function, String name) {
        if (name == null) {
            throw new IllegalArgumentException("Missing required variable name.");
        }
        for (Variable v : function.getAllVariables()) {
            if (name.equals(v.getName())) {
                return v;
            }
        }
        throw new IllegalArgumentException(
            "No variable named '" + name + "' in function " + function.getName() + ".");
    }

    /** SourceType from string (USER_DEFINED default). Accepts case-insensitive names. */
    public SourceType sourceType(String s) {
        return sourceType(s, SourceType.USER_DEFINED);
    }

    public SourceType sourceType(String s, SourceType dflt) {
        if (s == null || s.trim().isEmpty()) {
            return dflt;
        }
        try {
            return SourceType.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown source type: " + s
                + " (use USER_DEFINED, ANALYSIS, IMPORTED, DEFAULT).");
        }
    }

    /** Parse a C-style function signature string into a FunctionSignature. */
    public FunctionSignature parseSignature(String text) throws Exception {
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required signature text.");
        }
        FunctionSignature sig =
            new FunctionSignatureParser(program.getDataTypeManager(), null).parse(null, text);
        if (sig == null) {
            throw new IllegalArgumentException("Could not parse signature: " + text);
        }
        return sig;
    }

    /** A best-effort ServiceProvider for commands that need one (headless = no GUI services). */
    public ServiceProvider serviceProvider() {
        return new ServiceProviderStub();
    }

    /** A decompiler interface opened on this program. Caller MUST dispose() it. */
    public DecompInterface openedDecompiler() {
        DecompInterface di = new DecompInterface();
        di.openProgram(program);
        return di;
    }

    /** Read an optional int field; {@code dflt} when missing/null. */
    public static int optInt(JsonObject req, String field, int dflt) {
        return (req.has(field) && !req.get(field).isJsonNull())
            ? req.get(field).getAsInt() : dflt;
    }

    /** Read an optional boolean field; {@code dflt} when missing/null. */
    public static boolean optBool(JsonObject req, String field, boolean dflt) {
        return (req.has(field) && !req.get(field).isJsonNull())
            ? req.get(field).getAsBoolean() : dflt;
    }

    /** Read an optional string field; null when missing/null. */
    public static String optStr(JsonObject req, String field) {
        return (req.has(field) && !req.get(field).isJsonNull())
            ? req.get(field).getAsString() : null;
    }

    /** Read a required string field; throws when missing/empty. */
    public static String reqStr(JsonObject req, String field) {
        String v = optStr(req, field);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("Missing required field '" + field + "'.");
        }
        return v;
    }
}
