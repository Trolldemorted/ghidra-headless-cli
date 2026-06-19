package procedures.ghidra.program.model.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;

import procedures.RpcContext;

/**
 * Shared helpers for the datatype procedures.
 *
 * Conflict policy (per user direction): no automatic resolution. The handlers
 * use a strict {@link ghidra.program.model.data.DataTypeConflictHandler} that
 * throws on name conflict; the exception is caught and surfaced as a normal
 * {@code error} response so the caller sees the exact cause.
 */
final class DataTypeOps {

    /** Normalize a category path: leading slash, no trailing slash (root stays "/"). */
    static CategoryPath normalizePath(String path) {
        String p = (path == null || path.trim().isEmpty()) ? "/" : path.trim();
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        if (p.length() > 1 && p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        return new CategoryPath(p);
    }

    /** Resolve the category at {@code path} on the active program's DTM. */
    static Category requireCategory(RpcContext ctx, String path) {
        CategoryPath cp = normalizePath(path);
        Category cat = ctx.program().getDataTypeManager().getCategory(cp);
        if (cat == null) {
            throw new IllegalArgumentException("No data-type category found for '" + cp + "'.");
        }
        return cat;
    }

    /**
     * Resolve a type by its full path ({@code /Category/Sub/Name}) on the active
     * program's DTM. Built-in types ({@code /int}, {@code /char *}) resolve too;
     * callers should check {@link #isBuiltIn} before mutating. A single slash
     * between the (possibly empty) category prefix and the name means "root
     * category" — e.g. {@code "/byte"} → category {@code "/"}, name {@code "byte"}.
     *
     * <p><b>Archive-stub fallback.</b> When the program DTM has no entry at
     * {@code path} (e.g. the path lives only in an upstream archive like
     * {@code Battle_Realms_F.exe}, or the user just deleted a user-defined
     * type and the program's record of the category is now empty), the
     * merged view is searched: every {@link SourceArchive} is asked for
     * its types via {@link DataTypeManager#getDataTypes(SourceArchive)}, and
     * the first match wins. The result may be an archive-resolved stub.
     * Use {@link #isLocalProgramType} before mutating, and use
     * {@link #archiveName} to surface the source in error messages.
     */
    static DataType requireDataTypeByPath(RpcContext ctx, String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing data-type path.");
        }
        String p = path.trim();
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        DataTypeManager dtm = ctx.program().getDataTypeManager();
        int slash = p.lastIndexOf('/');
        // The first char must be '/' (we forced that above) and there must be
        // at least one char after it (the name). p = "/" alone has no name.
        if (p.length() < 2) {
            throw new IllegalArgumentException("Invalid data-type path '" + p + "'.");
        }
        String name = p.substring(slash + 1);
        if (name.isEmpty()) {
            throw new IllegalArgumentException("Invalid data-type path '" + p + "'.");
        }
        // category prefix is everything before the last '/'; the empty string
        // here means root ("/"), which CategoryPath("/") already represents.
        String catPrefix = slash == 0 ? "/" : p.substring(0, slash);
        CategoryPath cp = new CategoryPath(catPrefix);
        DataType dt = dtm.getDataType(cp, name);
        if (dt != null) {
            return dt;
        }
        // Fall back to the merged view: search every open source archive.
        // This is what makes `datatype show /Demangler/L_String` work when
        // /Demangler lives only in the Battle_Realms_F.exe archive.
        DataType stubMatch = null;
        int stubMatches = 0;
        for (SourceArchive arc : dtm.getSourceArchives()) {
            if (arc == null) continue;
            for (DataType t : dtm.getDataTypes(arc)) {
                if (!name.equals(t.getName())) continue;
                CategoryPath tcp = t.getCategoryPath();
                if (tcp == null) continue;
                String tCatPath = tcp.getName();
                String tFullPath = (tCatPath == null || tCatPath.isEmpty())
                    ? ("/" + t.getName())
                    : (tCatPath + "/" + t.getName());
                if (tFullPath.equals(p)) {
                    stubMatch = t;
                    stubMatches++;
                    if (stubMatches > 1) break;
                }
            }
            if (stubMatches > 1) break;
        }
        if (stubMatches > 1) {
            throw new IllegalArgumentException(
                "Multiple types match path '" + p + "' across open source archives; "
                + "this should not happen — please report as a bug.");
        }
        if (stubMatch == null) {
            throw new IllegalArgumentException("No data type at path '" + p + "'.");
        }
        return stubMatch;
    }

    /**
     * True when the type is a program-DTM type (user-defined or pulled in
     * by analysis) — i.e. it has no source archive, or its source archive
     * is the program's local archive. Archive-resolved stubs (from
     * upstream archives or built-ins) return false.
     */
    static boolean isLocalProgramType(DataType dt) {
        if (dt == null) return false;
        SourceArchive arc = dt.getSourceArchive();
        if (arc == null) return true;
        // Built-ins (int, char, etc.) are NOT local: they live in the
        // BUILT_IN_ARCHIVE_UNIVERSAL_ID archive.
        ghidra.util.UniversalID builtInId =
            ghidra.program.model.data.DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID;
        if (arc.getSourceArchiveID().equals(builtInId)) {
            return false;
        }
        // The program's local archive is identified by
        // DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID. A type whose
        // source archive is anything else is a non-local archive stub.
        ghidra.util.UniversalID localId =
            ghidra.program.model.data.DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
        return arc.getSourceArchiveID().equals(localId);
    }

    /**
     * Render a source archive's display name (or "(program)" for local
     * types, "(built-in)" for the canonical built-in archive). Useful
     * for human-readable error messages.
     */
    static String archiveName(DataType dt) {
        if (dt == null) return "(none)";
        SourceArchive arc = dt.getSourceArchive();
        if (arc == null) return "(program)";
        ghidra.util.UniversalID builtInId =
            ghidra.program.model.data.DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID;
        if (arc.getSourceArchiveID().equals(builtInId)) {
            return "(built-in)";
        }
        String n = arc.getName();
        return n == null || n.isEmpty() ? arc.getSourceArchiveID().toString() : n;
    }

    /**
     * Find every program-DTM type that depends on {@code target} — i.e.
     * the type references {@code target} through a field, base typedef,
     * pointer, array element, etc. Returns the referring types' absolute
     * paths (e.g. {@code "/OpCodes/OpRecord"}).
     *
     * <p>Used by {@link DeleteDataTypeHandler} to warn the caller that
     * deleting {@code target} will leave those referring composites with
     * {@code -BAD-} placeholders until each referrer is re-resolved (via
     * {@code datatype replace} of the referrer, or delete+create of the
     * referrer).
     *
     * <p>Implementation notes:
     * <ul>
     *   <li>Walks the program DTM only (not open source archives) — the
     *       archive stubs can't depend on a local type being deleted, and
     *       the response would be noisy otherwise.</li>
     *   <li>Why not {@link DataType#dependsOn(DataType)}? Empirically the
     *       Ghidra Composite/Structure implementation does NOT report a
     *       dependency on a field type that's been resolved into a
     *       different {@code DataType} instance via DTM name resolution
     *       (the field holds a pointer to one resolved instance; the
     *       caller passes a different instance of the same name). The
     *       result is empty referrer lists when there clearly are
     *       referrers. So we walk {@code getAllComponents()} ourselves
     *       and compare by full path, which is what the user actually
     *       cares about ("does any field reference MY type by name?").</li>
     *   <li>Skips {@code target} itself and built-in types — built-ins
     *       never reference a local type, and a type trivially "depends"
     *       on itself.</li>
     * </ul>
     */
    static List<String> findReferrers(DataTypeManager dtm, DataType target) {
        if (dtm == null || target == null) return Collections.emptyList();
        String targetPath = pathOf(target);
        if (targetPath == null) return Collections.emptyList();
        List<String> refs = new ArrayList<>();
        java.util.Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType t = it.next();
            if (t == null || t.equals(target)) continue;
            if (isBuiltInDirect(dtm, t)) continue;
            if (referencesByPath(t, targetPath)) {
                CategoryPath cp = t.getCategoryPath();
                String cat = (cp == null) ? "/" : cp.getName();
                String path = (cat == null || cat.isEmpty() || cat.equals("/"))
                    ? ("/" + t.getName())
                    : (cat + "/" + t.getName());
                refs.add(path);
            }
        }
        Collections.sort(refs);
        return refs;
    }

    /** Full path of a DataType (e.g. "/OpCodes/OpHeaderBytes"), or null if not resolvable. */
    private static String pathOf(DataType dt) {
        if (dt == null) return null;
        CategoryPath cp = dt.getCategoryPath();
        String cat = (cp == null) ? "" : cp.getName();
        if (cat == null || cat.isEmpty() || cat.equals("/")) {
            return "/" + dt.getName();
        }
        return cat + "/" + dt.getName();
    }

    /**
     * Recursive structural walk: does {@code t} reference a type whose
     * full path matches {@code targetPath}? Walks composites (components),
     * typedefs (base), arrays (element), pointers (dataType), function
     * definitions (parameter/return types), and parameter lists. Cycle-safe
     * via the {@code seen} set so a recursive typedef can't loop forever.
     */
    private static boolean referencesByPath(DataType t, String targetPath) {
        java.util.Set<DataType> seen = java.util.Collections.newSetFromMap(
            new java.util.IdentityHashMap<>());
        return referencesByPathRec(t, targetPath, seen);
    }

    private static boolean referencesByPathRec(DataType t, String targetPath,
            java.util.Set<DataType> seen) {
        if (t == null) return false;
        if (!seen.add(t)) return false;
        String p = pathOf(t);
        if (targetPath.equals(p)) return true;
        if (t instanceof ghidra.program.model.data.Composite) {
            ghidra.program.model.data.Composite c = (ghidra.program.model.data.Composite) t;
            for (int i = 0; i < c.getNumComponents(); i++) {
                ghidra.program.model.data.DataTypeComponent comp = c.getComponent(i);
                if (comp == null) continue;
                if (referencesByPathRec(comp.getDataType(), targetPath, seen)) {
                    return true;
                }
            }
        } else if (t instanceof ghidra.program.model.data.TypeDef) {
            return referencesByPathRec(
                ((ghidra.program.model.data.TypeDef) t).getBaseDataType(),
                targetPath, seen);
        } else if (t instanceof ghidra.program.model.data.Array) {
            return referencesByPathRec(
                ((ghidra.program.model.data.Array) t).getDataType(),
                targetPath, seen);
        } else if (t instanceof ghidra.program.model.data.Pointer) {
            return referencesByPathRec(
                ((ghidra.program.model.data.Pointer) t).getDataType(),
                targetPath, seen);
        } else if (t instanceof ghidra.program.model.data.FunctionDefinition) {
            ghidra.program.model.data.FunctionDefinition fd =
                (ghidra.program.model.data.FunctionDefinition) t;
            if (referencesByPathRec(fd.getReturnType(), targetPath, seen)) return true;
            ghidra.program.model.data.ParameterDefinition[] params = fd.getArguments();
            if (params != null) {
                for (ghidra.program.model.data.ParameterDefinition pd : params) {
                    if (referencesByPathRec(pd.getDataType(), targetPath, seen)) {
                        return true;
                    }
                }
            }
        }
        // Built-in scalars (int, char, float, ...) have no dependencies to
        // recurse into. EnumDataType is also scalar — its entries are
        // (name, value) pairs, not type references.
        return false;
    }

    /**
     * Built-in check that doesn't require an {@link RpcContext} — split
     * out from {@link #isBuiltIn} so {@link #findReferrers} can call it
     * inside its read-only DTM walk.
     */
    private static boolean isBuiltInDirect(DataTypeManager dtm, DataType dt) {
        if (dt == null) return false;
        SourceArchive arc = dt.getSourceArchive();
        if (arc == null) return false;
        SourceArchive builtInArc = dtm.getSourceArchive(
            ghidra.program.model.data.DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID);
        if (builtInArc == null) return false;
        return arc.getSourceArchiveID().equals(builtInArc.getSourceArchiveID());
    }

    /**
     * A type is built-in iff its source archive is the program's
     * {@link DataTypeManager#BUILT_IN_ARCHIVE_UNIVERSAL_ID} archive (the
     * canonical built-in source — "BuiltInTypes" / "BuiltIns" depending on
     * Ghidra version, plus things like ANSI_C and windows_vs that share the
     * same archive key). User-defined types in the root category are
     * editable; built-ins are not.
     *
     * Detection by archive name string is unreliable (the name varies across
     * Ghidra versions and per-program imports), so we compare the source
     * archive's {@link SourceArchive#getSourceArchiveID} against the manager's
     * BUILT_IN_ARCHIVE_UNIVERSAL_ID — that's the canonical Ghidra discriminator.
     */
    static boolean isBuiltIn(RpcContext ctx, DataType dt) {
        if (dt == null) return false;
        SourceArchive arc = dt.getSourceArchive();
        if (arc == null) return false;
        SourceArchive builtInArc = ctx.program().getDataTypeManager()
            .getSourceArchive(ghidra.program.model.data.DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID);
        if (builtInArc == null) return false;
        return arc.getSourceArchiveID().equals(builtInArc.getSourceArchiveID());
    }

    /** Convert a gson array of {name, type} objects to a List of (name, type) pairs. */
    static List<FieldPair> fieldList(JsonArray arr) {
        List<FieldPair> out = new ArrayList<>();
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            String name = o.has("name") && !o.get("name").isJsonNull()
                ? o.get("name").getAsString() : "";
            String type = o.has("type") && !o.get("type").isJsonNull()
                ? o.get("type").getAsString() : null;
            if (type == null || type.isEmpty()) {
                throw new IllegalArgumentException("Each field needs a 'type'.");
            }
            out.add(new FieldPair(name, type));
        }
        return out;
    }

    /** (name, value) pair for enum entries. */
    static final class EnumEntry {
        final String name;
        final long value;
        EnumEntry(String name, long value) { this.name = name; this.value = value; }
    }

    static List<EnumEntry> enumEntries(JsonArray arr) {
        List<EnumEntry> out = new ArrayList<>();
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            String name = o.get("name").getAsString();
            long val = o.get("value").getAsLong();
            out.add(new EnumEntry(name, val));
        }
        return out;
    }

    /** (name, type) pair for struct/union fields. */
    static final class FieldPair {
        final String name;
        final String type;
        FieldPair(String name, String type) { this.name = name; this.type = type; }
    }
}
