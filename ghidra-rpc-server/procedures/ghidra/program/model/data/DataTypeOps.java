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
 *
 * <p>Field-level mutators (set-field-comment, set-field-type,
 * set-field-name) share {@link #resolveFieldIndex} for the
 * {@code <name|@offset|N>} spec convention.
 */
public final class DataTypeOps {

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
     * program's DTM. Built-in types ({@code /int}, {@code char *}) resolve too;
     * callers should check {@link #isBuiltIn} before mutating. A single slash
     * between the (possibly empty) category prefix and the name means "root
     * category" — e.g. {@code "/byte"} → category {@code "/"}, name {@code "byte"}.
     *
     * <p><b>Three-tier fallback.</b> A literal {@code /Category/Name} lookup
     * is tried first (the program DTM); on miss, an
     * <b>archive-qualified path</b> is tried: the first segment is taken as
     * a {@link SourceArchive} name (with optional {@code " (archive)"}
     * suffix stripped — that's the form the {@code datatype list} output
     * prints in the {@code sourceArchive} column, which a user pasting
     * back as a path commonly re-introduces). When the first segment
     * matches a known archive (local OR upstream), the prefix is
     * stripped and the rest is retried as a normal {@code /Cat/Sub/Name}
     * path in the program DTM; this handles the case where the user
     * pasted a list-style path and the type's category is {@code /DOS},
     * {@code /PE}, etc. — not the user's mistake. On miss, the merged
     * view is searched: every {@link SourceArchive} is asked for its
     * types via {@link DataTypeManager#getDataTypes(SourceArchive)}, and
     * any type with the same full path wins. The first tier dominates:
     * a literal category path never falls through to the
     * archive-qualified interpretation. The result may be an
     * archive-resolved stub. Use {@link #isLocalProgramType} before
     * mutating, and use {@link #archiveName} to surface the source in
     * error messages.
     */
    public static DataType requireDataTypeByPath(RpcContext ctx, String path) {
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
        // Archive-qualified path: first segment is a SourceArchive name, the
        // rest is a /Cat/Sub/Name path. Recognised formats (all equivalent):
        //   /<prog>.exe-<hex> (archive)/DOS/IMAGE_DOS_HEADER
        //   /<prog>.exe-<hex>/DOS/IMAGE_DOS_HEADER
        //   /windows_vs/WinDef.h/HBITMAP__
        // The archive prefix is decoration: the type's REAL path is the rest.
        // We strip the prefix and retry the rest in the program DTM. This
        // covers the common case where the type's category is /DOS, /PE,
        // etc. — the user didn't make a mistake, they just copied the
        // archive-prefixed form that `datatype list` prints.
        if (p.indexOf('/', 1) > 0) {
            int secondSlash = p.indexOf('/', 1);
            String arcHead = p.substring(1, secondSlash);
            String arcRest = p.substring(secondSlash);   // e.g. "/DOS/IMAGE_DOS_HEADER"
            String arcName = stripArchiveSuffix(arcHead);
            if (isKnownArchiveName(dtm, arcName)) {
                // arcRest is "/Cat/Sub/Name" — split into category + name
                // and retry the literal lookup in the program DTM.
                int restSlash = arcRest.lastIndexOf('/');
                String restCat = restSlash <= 0 ? "/" : arcRest.substring(0, restSlash);
                String restName = arcRest.substring(restSlash + 1);
                DataType rest = dtm.getDataType(new CategoryPath(restCat), restName);
                if (rest != null) return rest;
                // No local match. If the archive is upstream, also search it.
                SourceArchive arc = findSourceArchiveByName(dtm, arcName);
                if (arc != null) {
                    for (DataType t : dtm.getDataTypes(arc)) {
                        if (restName.equals(t.getName()) && arcRest.equals(pathOf(t))) {
                            return t;
                        }
                    }
                }
                // Archive found, but the path within it is empty. Surface a
                // specific error so the user can disambiguate.
                throw new IllegalArgumentException(
                    "Source archive '" + arcHead + "' has no type at '" + arcRest
                    + "'. Pass `datatype show --name " + restName + " --archive "
                    + arcName + "` to enumerate its types with that name.");
            }
            // No matching archive — fall through to merged-view search.
        }
        // Fall back to the merged view: search every open source archive.
        // This is what makes `datatype show /Demangler/<name>` work when
        // /Demangler lives only in a non-local archive.
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
            throw new IllegalArgumentException(
                "No data type at path '" + p + "'. Pass `datatype list` to see "
                + "available paths, or `datatype show --name <name>` to look up by "
                + "leaf name across all categories and archives.");
        }
        return stubMatch;
    }

    /**
     * Resolve a type by its leaf {@code name} (with optional {@code archive}
     * filter and category scoping). Mirrors the {@code show} subcommand's
     * {@code --name / --archive} form. Search order:
     * <ol>
     *   <li>If {@code archive} is non-null/empty, restrict to types in that
     *       source archive (name match; the {@code " (archive)"} suffix
     *       Ghidra shows in lists is stripped automatically). If exactly one
     *       match, return it; if more, return the first and report the
     *       count. If zero, error.</li>
     *   <li>Otherwise, search the program DTM (every category) for an
     *       exact name match. If exactly one, return it; if more, error
     *       with the matching paths; if zero, fall through to the merged
     *       view.</li>
     *   <li>Search every open source archive for a type with that leaf
     *       name. Return the first match (with a note that the user
     *       should pass {@code --archive} to disambiguate if more
     *       exist).</li>
     * </ol>
     * {@code category}, when non-null/empty, scopes the program-DTM search
     * to a single category (e.g. {@code "/Demangler"}); archive search
     * is unaffected.
     */
    static DataType requireDataTypeByName(RpcContext ctx, String name, String archive, String category) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing data-type name.");
        }
        String nm = name.trim();
        DataTypeManager dtm = ctx.program().getDataTypeManager();
        if (archive != null && !archive.trim().isEmpty()) {
            String arcName = stripArchiveSuffix(archive.trim());
            SourceArchive arc = findSourceArchiveByName(dtm, arcName);
            if (arc == null) {
                throw new IllegalArgumentException("No open source archive named '"
                    + archive.trim() + "'. Use `datatype list` to see archive names.");
            }
            DataType match = null;
            int matches = 0;
            for (DataType t : dtm.getDataTypes(arc)) {
                if (nm.equals(t.getName())) {
                    if (match == null) match = t;
                    matches++;
                    if (matches > 1) break;
                }
            }
            if (matches == 0) {
                throw new IllegalArgumentException("Source archive '"
                    + arc.getName() + "' has no type named '" + nm + "'.");
            }
            if (matches > 1) {
                throw new IllegalArgumentException(
                    "Source archive '" + arc.getName() + "' has " + matches
                    + " types named '" + nm + "'. Use `datatype show --path` with "
                    + "the full archive-qualified path to disambiguate.");
            }
            return match;
        }
        // Program DTM first.
        CategoryPath cp = null;
        if (category != null && !category.trim().isEmpty()) {
            cp = normalizePath(category);
        }
        DataType dt = cp == null ? findInProgramByName(dtm, nm) : dtm.getDataType(cp, nm);
        if (dt != null) return dt;
        // No program-DTM match — fall back to merged view.
        DataType stubMatch = null;
        int stubMatches = 0;
        StringBuilder otherArchives = new StringBuilder();
        for (SourceArchive arc : dtm.getSourceArchives()) {
            if (arc == null) continue;
            for (DataType t : dtm.getDataTypes(arc)) {
                if (nm.equals(t.getName())) {
                    if (stubMatch == null) stubMatch = t;
                    stubMatches++;
                    if (otherArchives.length() < 3) {
                        if (otherArchives.length() > 0) otherArchives.append(", ");
                        otherArchives.append(arc.getName());
                    }
                    if (stubMatches > 1) break;
                }
            }
            if (stubMatches > 1) break;
        }
        if (stubMatches == 0) {
            throw new IllegalArgumentException("No data type named '" + nm
                + "'. Use `datatype list` to see available names.");
        }
        if (stubMatches > 1) {
            throw new IllegalArgumentException("Multiple types named '" + nm
                + "' across open source archives (" + otherArchives
                + "). Pass `--archive <name>` (or `--path` with the full path) to "
                + "disambiguate.");
        }
        return stubMatch;
    }

    /** Walk the program DTM for a type whose name matches {@code name} exactly. */
    private static DataType findInProgramByName(DataTypeManager dtm, String name) {
        java.util.Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType t = it.next();
            if (t == null) continue;
            if (name.equals(t.getName())) return t;
        }
        return null;
    }

    /**
     * Strip the {@code " (archive)"} / {@code " (builtin)"} / {@code " (user)"}
     * provenance suffix that {@code datatype list} adds to source archive
     * names. Case-insensitive; trailing whitespace tolerated.
     */
    private static String stripArchiveSuffix(String s) {
        String r = s.trim();
        for (String suf : new String[] {" (archive)", " (builtin)", " (user)"}) {
            if (r.length() > suf.length()
                && r.toLowerCase().endsWith(suf.toLowerCase())) {
                return r.substring(0, r.length() - suf.length());
            }
        }
        return r;
    }

    /**
     * Find a {@link SourceArchive} on the program DTM by case-insensitive
     * name match. Returns null when no archive matches.
     */
    private static SourceArchive findSourceArchiveByName(DataTypeManager dtm, String name) {
        for (SourceArchive arc : dtm.getSourceArchives()) {
            if (arc == null) continue;
            String an = arc.getName();
            if (an == null) continue;
            if (an.equalsIgnoreCase(name)) return arc;
        }
        // Also check the local DTM's archive — types defined in the
        // program itself live there. The local archive's name comes from
        // the program's domain-file stem (e.g. "Mapeditor.exe" for a
        // program imported as /Mapeditor.exe). Fetch it via the local
        // archive's universal ID; if the API call returns null (some
        // Ghidra builds don't expose the local archive this way), fall
        // back to walking all data types and finding an archive whose
        // name matches — that's what the `sourceArchive` field in
        // `datatype list` output is sourced from anyway.
        SourceArchive localArc = dtm.getSourceArchive(
            ghidra.program.model.data.DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID);
        if (localArc != null && localArc.getName() != null
            && localArc.getName().equalsIgnoreCase(name)) {
            return localArc;
        }
        // Last-ditch: walk all types and find the first whose source
        // archive's name matches. Slower, but catches builds where
        // getSourceArchive(LOCAL) doesn't return the archive.
        java.util.Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType t = it.next();
            if (t == null) continue;
            SourceArchive arc = t.getSourceArchive();
            if (arc == null) continue;
            String an = arc.getName();
            if (an != null && an.equalsIgnoreCase(name)) return arc;
        }
        return null;
    }

    /**
     * True when {@code name} matches a known source archive (upstream or
     * local). Used by {@link #requireDataTypeByPath} to detect when the
     * first path segment is an archive name (e.g. the form
     * {@code /Mapeditor.exe (archive)/IMAGE_DOS_HEADER} that
     * {@code datatype list} prints) rather than a category.
     */
    private static boolean isKnownArchiveName(DataTypeManager dtm, String name) {
        return findSourceArchiveByName(dtm, name) != null;
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
     * Full path of a DataType (e.g. "/OpCodes/OpHeaderBytes"), or null if not resolvable.
     */
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
                refs.add(pathOf(t));
            }
        }
        Collections.sort(refs);
        return refs;
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

    /**
     * Resolve a user-supplied field spec to a component index. Three forms:
     * <ul>
     *   <li>all-digit non-negative string (e.g. {@code "5"}) — literal
     *       index, bounds-checked against the composite's component count.</li>
     *   <li>{@code @0xN} or {@code @0XN} (e.g. {@code "@0x10"}) — byte
     *       offset into a {@link ghidra.program.model.data.Structure}.
     *       Rejected on unions (all components share offset 0; use name
     *       or index instead).</li>
     *   <li>anything else — first field-name match. Ambiguous (multiple
     *       matches) is an error so the caller can disambiguate by
     *       index or offset.</li>
     * </ul>
     * Shared by {@code SetDataTypeFieldComment}, {@code SetDataTypeFieldType},
     * and {@code SetDataTypeFieldName}. All-digits is treated as an
     * index (not a hex offset) for consistency with the pre-2026-06-24
     * behavior; the new {@code @0xN} form is the only way to address by
     * byte offset.
     *
     * @param composite the struct or union to address into
     * @param field the user-supplied spec; see the rules above
     * @param path the type's full path, used in error messages
     * @return the resolved component index
     * @throws IllegalArgumentException on any failure to resolve
     */
    static int resolveFieldIndex(ghidra.program.model.data.Composite composite,
                                 String field, String path) {
        Integer asIndex = tryParseIndex(field);
        if (asIndex != null) {
            int n = composite.getNumComponents();
            if (asIndex < 0 || asIndex >= n) {
                throw new IllegalArgumentException("Field index " + asIndex
                    + " out of range for '" + path + "' (valid: 0.." + (n - 1) + ").");
            }
            return asIndex;
        }
        if (field.startsWith("@")) {
            // @offset form — struct-only. Unions have all components at
            // offset 0, so the form is meaningless; reject up front with
            // a clear message rather than letting getComponentContaining
            // return the first component and look like it "worked".
            if (composite instanceof ghidra.program.model.data.Union) {
                throw new IllegalArgumentException(
                    "@offset form is not supported on unions (all components share "
                  + "offset 0); use the field name or numeric index instead.");
            }
            Integer offset = tryParseOffset(field.substring(1));
            if (offset == null) {
                throw new IllegalArgumentException(
                    "Invalid @offset form '" + field + "': expected @0xN (hex).");
            }
            ghidra.program.model.data.Structure s = (ghidra.program.model.data.Structure) composite;
            ghidra.program.model.data.DataTypeComponent c = s.getComponentContaining(offset);
            if (c == null) {
                throw new IllegalArgumentException("No component at offset 0x"
                    + Integer.toHexString(offset) + " in '" + path
                    + "'. Available offsets: " + availableOffsets(s));
            }
            return c.getOrdinal();
        }
        // Name search: first match wins; ambiguity is an error so the
        // caller can disambiguate by index or @offset.
        int match = -1;
        for (int i = 0; i < composite.getNumComponents(); i++) {
            ghidra.program.model.data.DataTypeComponent c = composite.getComponent(i);
            if (c == null) continue;
            if (field.equals(c.getFieldName())) {
                if (match != -1) {
                    throw new IllegalArgumentException("Field name '" + field
                        + "' is ambiguous in '" + path + "' (matches at least indices "
                        + match + " and " + i + "); use the index or @offset instead.");
                }
                match = i;
            }
        }
        if (match == -1) {
            throw new IllegalArgumentException("Field '" + field + "' not found in '" + path
                + "'. Available fields: " + availableFields(composite));
        }
        return match;
    }

    /** Parse a positive integer string; null if not a clean non-negative int. */
    private static Integer tryParseIndex(String s) {
        if (s == null || s.isEmpty() || s.length() > 9) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
        }
        try {
            int n = Integer.parseInt(s);
            return n >= 0 ? n : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Parse a {@code "0xN"} or {@code "0XN"} hex string. Returns null if
     * the prefix is missing, the suffix contains non-hex chars, or the
     * parsed value overflows int. The {@code 0x} prefix is REQUIRED
     * (the field-spec convention deliberately distinguishes hex offsets
     * from decimal indices so all-digit values are unambiguous).
     */
    private static Integer tryParseOffset(String s) {
        if (s == null || s.length() < 3) return null;
        if (s.charAt(0) != '0' || (s.charAt(1) != 'x' && s.charAt(1) != 'X')) {
            return null;
        }
        for (int i = 2; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return null;
            }
        }
        try {
            return Integer.parseInt(s.substring(2), 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** List up to 5 field names for the not-found / ambiguous error message. */
    private static String availableFields(ghidra.program.model.data.Composite composite) {
        StringBuilder sb = new StringBuilder("[");
        int n = Math.min(5, composite.getNumComponents());
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            ghidra.program.model.data.DataTypeComponent c = composite.getComponent(i);
            String name = c == null ? "?" : c.getFieldName();
            sb.append(name == null ? "(unnamed)" : name);
        }
        if (composite.getNumComponents() > 5) {
            sb.append(", ...");
        }
        sb.append(']');
        return sb.toString();
    }

    /**
     * List up to 5 byte offsets for the "no component at @offset" error
     * message. Offsets are formatted as {@code 0xN} to match the input
     * convention; ordinals in brackets when components are unnamed.
     */
    private static String availableOffsets(ghidra.program.model.data.Structure s) {
        StringBuilder sb = new StringBuilder("[");
        int n = Math.min(5, s.getNumComponents());
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            ghidra.program.model.data.DataTypeComponent c = s.getComponent(i);
            if (c == null) {
                sb.append("?");
            } else {
                int off = c.getOffset();
                sb.append("0x").append(Integer.toHexString(off));
                String fn = c.getFieldName();
                if (fn != null && !fn.isEmpty()) {
                    sb.append(" ('").append(fn).append("')");
                }
            }
        }
        if (s.getNumComponents() > 5) {
            sb.append(", ...");
        }
        sb.append(']');
        return sb.toString();
    }

    /** (name, type) pair for struct/union fields. */
    static final class FieldPair {
        final String name;
        final String type;
        FieldPair(String name, String type) { this.name = name; this.type = type; }
    }
}
