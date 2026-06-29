package procedures.ghidra.program.model.data;

import java.util.regex.Pattern;

/**
 * Post-processor for {@link ghidra.program.model.data.DataTypeWriter}
 * output. {@code DataTypeWriter} unconditionally emits a builtins
 * preamble ({@code typedef unsigned char byte; typedef unsigned int
 * dword;} ... twenty-something lines) and follows dependencies of the
 * requested type, so the raw writer output is hundreds of lines for
 * a single struct. The CLI user wants the requested type alone
 * unless they opt into the full dependency graph.
 *
 * <p>Strategy: parse the writer's output line-by-line and keep only
 * the lines that constitute the requested type's C block.
 *
 * <ul>
 *   <li><b>struct/union {@code Foo}</b>:
 *     <pre>
 *     typedef struct Foo Foo, *PFoo;
 *     struct Foo {
 *         ...fields...
 *     };
 *     </pre>
 *     We keep from the forward decl (the {@code typedef struct Foo Foo,
 *     *PFoo;} line) through the body's closing {@code };}.</li>
 *
 *   <li><b>enum {@code Foo}</b>:
 *     <pre>
 *     typedef enum Foo { RED, GREEN, BLUE } Foo;
 *     </pre>
 *     (or {@code #define Foo v;} for single-value {@code define_*}
 *     enums — but in practice the type enum form is what the user
 *     sees). We keep the single block from the opening
 *     {@code typedef enum Foo} to its matching {@code } Foo;}.</li>
 *
 *   <li><b>typedef {@code Foo}</b>:
 *     <pre>typedef unsigned int Foo;</pre>
 *     Just the single line, identified by the requested name on the
 *     LHS of the trailing semicolon (word-boundary on either side).</li>
 *
 *   <li><b>built-in primitive {@code Foo}</b> (e.g. {@code byte},
 *     {@code dword}): the writer's output IS the preamble, and the
 *     preamble IS the requested type's declaration. We return the
 *     full output (with all the other builtins). The user
 *     explicitly opted into built-ins by asking for one.</li>
 * </ul>
 *
 * <p>Identifier matching uses word boundaries — the writer is free
 * to embed {@code Foo} in another type's display name (e.g. a struct
 * called {@code Food} would share the prefix {@code Foo}). A
 * naïve substring match would over-keep.
 */
public final class CDeclarationFilter {

    private CDeclarationFilter() { }

    /**
     * @param raw  the full output of {@code DataTypeWriter.write(...)}.
     * @param kind one of {@code "struct"}, {@code "union"}, {@code "enum"},
     *             {@code "typedef"}, {@code "primitive"}, etc. (same set
     *             as {@code DataTypeSerializer.kindOf}).
     * @param name the type's display name (last segment of its path).
     * @return the requested type's C block, or the full input if no
     *         matching block could be identified (defensive — caller
     *         already has the raw output to show on error).
     */
    public static String filter(String raw, String kind, String name) {
        if (raw == null || raw.isEmpty()) return raw;
        if (name == null || name.isEmpty()) return raw;
        if (kind == null) return raw;

        // Built-ins: the requested type's declaration IS in the preamble;
        // there's nothing to strip (the user got a builtin when they
        // asked for one). Pass through.
        if ("primitive".equals(kind)) {
            return raw;
        }

        switch (kind) {
            case "struct":
            case "union":
                return filterComposite(raw, kind, name);
            case "enum":
                return filterEnum(raw, name);
            case "typedef":
                return filterTypedef(raw, name);
            default:
                // Unknown kind (e.g. pointer, array, functiondef, bitfield).
                // The writer emits a single declaration line for these —
                // find the line that names the type and return just it
                // (with a leading typedef if the writer produced one).
                return filterTypedef(raw, name);
        }
    }

    /**
     * For struct/union {@code Foo}: keep the {@code typedef struct Foo
     * Foo, *PFoo;} line, the {@code struct Foo {};` body, and any
     * typedefs that the writer emitted inline before the body for
     * the struct's field types. After the body ends, stop.
     *
     * <p>Why include inline typedefs before the body: the writer's
     * dependency-following emits typedefs for any typedefs the struct's
     * fields reference. These appear in the output BEFORE the
     * {@code struct Foo {` line (because that's how the writer
     * orders things), not in the preamble. The user wants them
     * because the struct won't compile without them.
     */
    private static String filterComposite(String raw, String kind, String name) {
        String[] lines = raw.split("\n", -1);
        StringBuilder out = new StringBuilder();
        boolean inBlock = false;
        int braceDepth = 0;
        Pattern fwdDecl = Pattern.compile(
            "^\\s*typedef\\s+" + kind + "\\s+\\Q" + name + "\\E\\s+\\Q" + name
            + "\\E\\s*,\\s*\\*P?\\Q" + name + "\\E\\s*;\\s*$");
        Pattern bodyStart = Pattern.compile(
            "^\\s*" + kind + "\\s+\\Q" + name + "\\E\\s*\\{\\s*$");
        for (String line : lines) {
            if (!inBlock) {
                // Look for the forward decl OR the body start. The
                // writer places the forward decl of the requested type
                // AFTER the builtins preamble; field-referenced
                // typedefs (e.g. for a field of type `uint`) appear
                // AFTER the forward decl but BEFORE the body (see
                // writeDeferredDeclarations in DataTypeWriter), so we
                // do NOT need to scan pre-fwd-decl lines for "field
                // typedefs" — those live in our output range.
                if (fwdDecl.matcher(line).matches() || bodyStart.matcher(line).matches()) {
                    inBlock = true;
                    out.append(line).append('\n');
                    if (bodyStart.matcher(line).matches()) {
                        braceDepth = 1;
                    }
                }
                // Drop everything before the fwd decl/body (preamble).
            } else {
                out.append(line).append('\n');
                if (bodyStart.matcher(line).matches()) {
                    braceDepth = 1;
                } else {
                    for (int i = 0; i < line.length(); i++) {
                        char c = line.charAt(i);
                        if (c == '{') braceDepth++;
                        else if (c == '}') braceDepth--;
                    }
                    if (braceDepth == 0 && line.contains(";")) {
                        break;
                    }
                }
            }
        }
        return out.length() == 0 ? raw : stripTrailingBlank(out);
    }

    private static String filterEnum(String raw, String name) {
        // typedef enum Foo { ... } Foo;
        // #define Foo v;  (single-value define_* enums)
        String[] lines = raw.split("\n", -1);
        StringBuilder out = new StringBuilder();
        Pattern start = Pattern.compile(
            "^\\s*(typedef\\s+enum\\s+\\Q" + name + "\\E\\s*\\{|#define\\s+\\Q" + name
            + "\\E\\s+)");
        for (String line : lines) {
            if (start.matcher(line).find()) {
                out.append(line).append('\n');
                // Single-line case: #define Foo v;  already complete.
                if (line.trim().endsWith(";") && !line.contains("{")) {
                    break;
                }
                // Multi-line: read until the matching `} NAME;`.
                // We've already written the opening line. Keep going
                // until we see `} NAME;` on a line.
                int i = java.util.Arrays.asList(lines).indexOf(line);
                for (int j = i + 1; j < lines.length; j++) {
                    String l = lines[j];
                    out.append(l).append('\n');
                    if (l.matches("^\\s*\\}\\s*\\Q" + name + "\\E\\s*;\\s*$")) {
                        return stripTrailingBlank(out);
                    }
                }
                break;
            }
        }
        return out.length() == 0 ? raw : stripTrailingBlank(out);
    }

    private static String filterTypedef(String raw, String name) {
        // The writer emits `typedef <base> <name>;` for the typedef.
        // The base may itself be a typedef (e.g. `typedef unsigned int
        // uint32; typedef uint32 my_int;`) — but the writer emits only
        // the requested typedef, so we just need the line ending in
        // `; NAME;` (word-boundary).
        String[] lines = raw.split("\n", -1);
        Pattern singleTypedef = Pattern.compile(
            "^\\s*typedef\\s+.*\\s+\\Q" + name + "\\E\\s*;\\s*$");
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            if (singleTypedef.matcher(line).matches()) {
                out.append(line).append('\n');
                break;
            }
        }
        return out.length() == 0 ? raw : stripTrailingBlank(out);
    }

    private static String stripTrailingBlank(StringBuilder sb) {
        if (sb.length() == 0) return sb.toString();
        // Trim exactly one trailing newline (the writer's lines are
        // each newline-terminated). If there's an empty trailing
        // line, leave it for the caller to handle.
        if (sb.charAt(sb.length() - 1) == '\n') {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }
}
