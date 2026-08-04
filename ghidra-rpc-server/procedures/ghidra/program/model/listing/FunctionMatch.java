package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.symbol.Namespace;

/**
 * One matched function in a function-search response; serialized by gson.
 *
 * <p>Stable wire schema (added 2026-08-04):
 * <ul>
 *   <li>{@code name} — leaf name (the function's {@link Function#getName()}).</li>
 *   <li>{@code address} — entry-point address, formatted by
 *       {@link ghidra.program.model.address.Address#toString()} (e.g. {@code "0x00401060"}).</li>
 *   <li>{@code tags} — every {@link FunctionTag} name attached to the
 *       function, sorted, on tag and "all" searches; {@code null} on
 *       name / address searches to keep the payload small.</li>
 *   <li>{@code tag} — the first tag (or {@code null} when the function has
 *       none) so structured consumers can keep a single-column field for
 *       "is this the entry-point / hot path" without joining the array.</li>
 *   <li>{@code isThunk} — {@link Function#isThunk()}. Lets downstream
 *       consumers filter thunks without parsing names.</li>
 *   <li>{@code namespace} — qualified parent namespace name with
 *       {@code "::"} separators, or {@code null} for top-level functions.
 *       Computed via {@link Namespace#getName(boolean)} on
 *       {@link Function#getParentNamespace()}. The leaf name is NOT
 *       included (use {@code name} for the leaf, prepend
 *       {@code namespace + "::"} for the qualified form).</li>
 * </ul>
 *
 * <p>Backward compatibility: the original three fields are unchanged.
 * New fields are added and serialized alongside.
 */
final class FunctionMatch {
    final String name;
    final String address;
    final List<String> tags;    // populated by tag / all searches; null on name / address
    final String tag;           // primary tag (first element of tags), or null
    final boolean isThunk;
    final String namespace;     // qualified parent namespace ("A::B::C"), or null at root

    FunctionMatch(String name, String address, List<String> tags,
            boolean isThunk, String namespace) {
        this.name = name;
        this.address = address;
        this.tags = tags;
        this.tag = (tags == null || tags.isEmpty()) ? null : tags.get(0);
        this.isThunk = isThunk;
        this.namespace = namespace;
    }

    /**
     * Build from a {@link Function}. Tags are populated only when
     * {@code includeTags} is true — name / address searches pass false
     * to keep the payload minimal (matches the pre-2026-08-04 behavior).
     */
    static FunctionMatch from(Function f, boolean includeTags) {
        List<String> tagList = includeTags ? tagsOf(f) : null;
        return new FunctionMatch(
            f.getName(),
            f.getEntryPoint().toString(),
            tagList,
            f.isThunk(),
            parentNamespaceName(f));
    }

    private static List<String> tagsOf(Function f) {
        List<String> tags = new ArrayList<>();
        for (FunctionTag t : f.getTags()) {
            tags.add(t.getName());
        }
        Collections.sort(tags);
        return tags;
    }

    /**
     * Qualified parent namespace name. Uses
     * {@link Namespace#getName(boolean)} with {@code true} for
     * qualified form. Returns {@code null} for top-level functions so
     * the wire field is absent on the common case rather than the
     * string {@code "Global"}.
     */
    private static String parentNamespaceName(Function f) {
        Namespace parent = f.getParentNamespace();
        if (parent == null || parent.isGlobal()) {
            return null;
        }
        String name = parent.getName(true);
        return (name == null || name.isEmpty()) ? null : name;
    }
}