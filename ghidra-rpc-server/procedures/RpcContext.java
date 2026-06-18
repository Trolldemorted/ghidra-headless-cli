package procedures;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
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
 * PROGRAM SELECTION: the server is not bound to a single program. Every
 * program-related procedure (see {@link RpcProcedure#needsProgram()}) carries a
 * mandatory {@code "file"} field — the target's project path (e.g.
 * {@code "/Mapeditor.exe"}). {@link #dispatch} resolves it once per request via
 * {@link #openProgram}, opening (and caching) the program from the project, and stores
 * it as the request's {@linkplain #active() active program}. All resolvers
 * ({@link #requireAddress}, {@link #requireFunctionAt}, {@link #applyCommand}, ...)
 * operate on that active program, so the procedure handlers never name it explicitly.
 *
 * SYNCHRONIZATION: a single {@link #lock} (ReentrantLock) serializes the ENTIRE
 * lifecycle of every request — program resolution, checkout, the procedure's mutation,
 * and the check-in — because Ghidra's program database is not safe for concurrent
 * mutation. {@link #dispatch} holds the lock from before {@link #openProgram} until
 * after check-in, so resolution+mutation+push are atomic with respect to other clients;
 * no other client can interleave a read or write in between. The lock is reentrant so a
 * procedure may call {@link #runWrite}/{@link #applyCommand} (which open program
 * transactions) without deadlock. The per-request {@link #active} field is only ever
 * read or written by the lock-holding thread inside the locked region, so it needs no
 * separate guard. The open-program cache is likewise only touched under the lock.
 */
public class RpcContext {

    private final Project project;
    private final TaskMonitor monitor;

    /** Open programs by canonical project path. Guarded by {@link #lock}. */
    private final Map<String, Program> open = new HashMap<>();

    /** Programs WE opened (and must release on shutdown). Guarded by {@link #lock}. */
    private final List<Program> owned = new ArrayList<>();

    /** The program selected for the in-flight request; set/cleared by {@link #dispatch} under {@link #lock}. */
    private Program active;

    /** Serializes the whole request lifecycle (see class doc). Reentrant for nested runWrite. */
    private final ReentrantLock lock = new ReentrantLock();

    /**
     * Create a context bound to {@code project} with ZERO open programs. The server starts
     * empty: every program is opened on demand by {@link #openProgram} when a request names
     * it. The program analyzeHeadless processed to invoke this script is only a trigger and
     * is intentionally NOT seeded here (see RpcServer).
     */
    public RpcContext(Project project, TaskMonitor monitor) {
        this.project = project;
        this.monitor = monitor;
    }

    /** The program selected for the current request; throws if none is active. */
    public Program program() {
        return active();
    }

    private Program active() {
        Program p = active;
        if (p == null) {
            throw new IllegalStateException("No program is selected for this request.");
        }
        return p;
    }

    public TaskMonitor monitor() {
        return monitor;
    }

    /** The project the server is bound to; for project-level procedures (e.g. import). */
    public Project project() {
        return project;
    }

    /**
     * Resolve a project path (or bare name, like program resolution) to its
     * {@link DomainFile}. Unlike {@link #program()} this does NOT open or check out the
     * file — it inspects the project tree only, so it works for any content type and any
     * file regardless of checkout state. Throws {@link IllegalArgumentException} if the
     * project is unavailable or no such file exists.
     */
    public DomainFile requireDomainFile(String path) {
        if (project == null) {
            throw new IllegalArgumentException(
                "No project is available; cannot select file '" + path + "'.");
        }
        DomainFile df = resolveFile(path);
        if (df == null) {
            throw new IllegalArgumentException("No file found for '" + path + "'.");
        }
        return df;
    }

    // ---------------------------------------------------------------------------
    // Dispatch: select program -> checkout -> execute -> (if mutating) checkin,
    // all under one lock.
    // ---------------------------------------------------------------------------

    /**
     * Run a procedure with exclusive program access. Holds {@link #lock} across the
     * whole sequence so program selection, checkout, mutation and check-in cannot
     * interleave with other clients. For program-related procedures the mandatory
     * {@code "file"} field selects the target; per policy the file is checked out
     * first and every successful mutating procedure is checked in immediately (the call
     * fails if the push fails).
     */
    public RpcResponse dispatch(RpcProcedure procedure, JsonObject request) throws Exception {
        lock.lock();
        try {
            Program program = null;
            if (procedure.needsProgram()) {
                String path = optStr(request, "file");
                if (path == null || path.isEmpty()) {
                    return RpcResponse.error("Missing required field 'file'.");
                }
                try {
                    program = openProgram(path); // checks the file out before opening it
                } catch (Exception e) {
                    return RpcResponse.error(message(e));
                }
            }
            active = program;
            try {
                RpcResponse response = procedure.execute(request, this);
                if (response != null && response.success && procedure.mutates() && program != null) {
                    RpcResponse checkinError = checkin(program, procedureOf(request));
                    if (checkinError != null) {
                        return checkinError; // push failed -> the whole call fails
                    }
                }
                return response;
            } finally {
                active = null;
            }
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

    // ---------------------------------------------------------------------------
    // Program resolution (project-level). Called only under {@link #lock}.
    // ---------------------------------------------------------------------------

    /**
     * Open (and cache) the program at {@code path}. {@code path} is a project path
     * (e.g. {@code "/Mapeditor.exe"}); a bare name with no {@code '/'} is also accepted
     * and resolved by a recursive name search. Returns the cached instance on repeat
     * calls. Throws {@link IllegalArgumentException} if no such program exists.
     */
    private Program openProgram(String path) throws Exception {
        if (project == null) {
            throw new IllegalArgumentException(
                "No project is available; cannot select program '" + path + "'.");
        }
        DomainFile df = resolveFile(path);
        if (df == null) {
            throw new IllegalArgumentException("No program found for '" + path + "'.");
        }
        String key = normalize(df.getPathname());
        Program cached = open.get(key);
        if (cached != null) {
            return cached;
        }
        if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
            throw new IllegalArgumentException("'" + df.getPathname() + "' is not a Program.");
        }
        // Check out BEFORE opening: a versioned file opened while not checked out yields a
        // read-only in-memory instance whose check-in would fail. On a read-only session we
        // skip checkout — read-only procedures still work; mutating ones fail later at check-in.
        if (df.isVersioned() && !df.isCheckedOut() && !df.isReadOnly()) {
            if (!df.checkout(true, monitor)) { // exclusive
                throw new IllegalArgumentException(
                    "Failed to check out '" + df.getPathname() + "' (held by another user?).");
            }
        }
        // okToUpgrade=true (open older DB versions), okToRecover=false. We are the consumer.
        Program p = (Program) df.getDomainObject(this, true, false, monitor);
        open.put(key, p);
        owned.add(p);
        return p;
    }

    /** Resolve a project path or bare program name to a DomainFile, or null. */
    private DomainFile resolveFile(String path) {
        DomainFile df = project.getProjectData().getFile(normalize(path));
        if (df != null) {
            return df;
        }
        // Fall back to a recursive search by simple name (no folder qualifier given).
        String name = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
        return findByName(project.getProjectData().getRootFolder(), name);
    }

    private DomainFile findByName(DomainFolder folder, String name) {
        for (DomainFile f : folder.getFiles()) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            DomainFile f = findByName(sub, name);
            if (f != null) {
                return f;
            }
        }
        return null;
    }

    private static String normalize(String path) {
        String t = path.trim();
        return t.startsWith("/") ? t : "/" + t;
    }

    /** Release every program we opened. Call on shutdown; leaves the context empty. */
    public void closeAll() {
        lock.lock();
        try {
            for (Program p : owned) {
                try {
                    p.release(this);
                } catch (Exception ignored) {
                    // best-effort teardown
                }
            }
            owned.clear();
            open.clear();
        } finally {
            lock.unlock();
        }
    }

    // ---------------------------------------------------------------------------
    // Checkout / check-in (per resolved program). Called only under {@link #lock}.
    // ---------------------------------------------------------------------------

    /**
     * Save + check {@code program}'s file in to the shared server so the change is
     * immediately visible to other clients. Returns null on success (or nothing to
     * push) and an error response if the push fails (per policy the whole call fails).
     */
    private RpcResponse checkin(Program program, String procedure) {
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
    // Command execution helpers (operate on the active program)
    // ---------------------------------------------------------------------------

    /** A unit of program mutation that may throw. */
    public interface Write {
        void run() throws Exception;
    }

    /**
     * Run {@code body} inside a transaction on the active program (committed iff it
     * returns normally; otherwise rolled back and rethrown). Always called while
     * holding {@link #lock}.
     */
    public void runWrite(String description, Write body) throws Exception {
        Program program = active();
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
     * Apply a Ghidra {@link Command} to the active program inside a transaction and map
     * the result to a response. Background commands get the real monitor.
     */
    public RpcResponse applyCommand(Command<Program> cmd) throws Exception {
        Program program = active();
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
    // Resolvers (operate on the active program; throw IllegalArgumentException ->
    // turned into error responses)
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
            return active().getAddressFactory().getAddress(s);
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
        Function f = active().getFunctionManager().getFunctionAt(entry);
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
        DataTypeManager dtm = active().getDataTypeManager();
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
        Register r = active().getRegister(name.trim());
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
            new FunctionSignatureParser(active().getDataTypeManager(), null).parse(null, text);
        if (sig == null) {
            throw new IllegalArgumentException("Could not parse signature: " + text);
        }
        return sig;
    }

    /** A best-effort ServiceProvider for commands that need one (headless = no GUI services). */
    public ServiceProvider serviceProvider() {
        return new ServiceProviderStub();
    }

    /** A decompiler interface opened on the active program. Caller MUST dispose() it. */
    public DecompInterface openedDecompiler() {
        DecompInterface di = new DecompInterface();
        di.openProgram(active());
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

    // ---------------------------------------------------------------------------
    // Brief request summary for server-side logging.
    // ---------------------------------------------------------------------------

    /**
     * Cap on a single value's text length when summarised for the server log.
     * Anything longer is truncated with a trailing {@code "..."} so each call
     * fits on one log line. 200 chars matches the convention in our notes and
     * is enough to identify a request without dumping full payloads.
     */
    public static final int BRIEF_VALUE_MAX = 200;

    /**
     * Render a request's arguments as a single greppable line for the server
     * log: alphabetically-sorted {@code key=value} pairs, space-separated.
     * The {@code procedure} field is omitted (caller already prefixes it).
     * String values longer than {@link #BRIEF_VALUE_MAX} are truncated with a
     * trailing {@code "..."}; nested objects and arrays are summarised by
     * length (e.g. {@code [tags:2]}). Designed never to throw and never to
     * return null.
     */
    public static String briefArgs(JsonObject req) {
        if (req == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        java.util.TreeMap<String, String> sorted = new java.util.TreeMap<>();
        for (java.util.Map.Entry<String, JsonElement> e : req.entrySet()) {
            String k = e.getKey();
            if ("procedure".equals(k)) {
                continue;
            }
            sorted.put(k, OPAQUE_FIELDS.contains(k)
                ? opaqueSummary(e.getValue())
                : briefValue(e.getValue()));
        }
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : sorted.entrySet()) {
            if (!first) sb.append(' ');
            first = false;
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    /** Render one JSON value as a brief log fragment; never throws, never null. */
    private static String briefValue(JsonElement v) {
        if (v == null || v.isJsonNull()) {
            return "null";
        }
        if (v.isJsonPrimitive()) {
            String s = v.getAsString();
            return truncate(s == null ? v.toString() : s);
        }
        if (v.isJsonArray()) {
            return "[" + v.getAsJsonArray().size() + "]";
        }
        if (v.isJsonObject()) {
            return "{" + v.getAsJsonObject().size() + "}";
        }
        return truncate(v.toString());
    }

    /**
     * Field names whose values are always logged as length only, never as
     * content. {@code bytes} is base64 of a whole binary on ProgramLoader and
     * a raw read on ReadBytes — the contents are unreadable in the log, take
     * hundreds of lines to dump, and risk leaking the input binary into log
     * aggregation. Add more here as we find them.
     */
    private static final java.util.Set<String> OPAQUE_FIELDS =
        java.util.Set.of("bytes");

    /**
     * Length-only summary for a value we treat as opaque (no content in the
     * log). For strings: byte/char count. For arrays/objects: element count.
     * Falls back to {@code "?"} for nulls/primitives we don't expect here.
     */
    private static String opaqueSummary(JsonElement v) {
        if (v == null || v.isJsonNull()) {
            return "?";
        }
        if (v.isJsonPrimitive()) {
            return String.valueOf(v.getAsString().length());
        }
        if (v.isJsonArray()) {
            return "[" + v.getAsJsonArray().size() + "]";
        }
        if (v.isJsonObject()) {
            return "{" + v.getAsJsonObject().size() + "}";
        }
        return "?";
    }

    /** Trim {@code s} to {@link #BRIEF_VALUE_MAX} chars, appending "..." if cut. */
    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        if (s.length() <= BRIEF_VALUE_MAX) {
            return s;
        }
        return s.substring(0, BRIEF_VALUE_MAX) + "...";
    }
}
