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
     * For struct/union {@code Foo}: keep every single-line forward-decl
     * typedef ({@code typedef struct Bar Bar, *PBar;}) plus the
     * requested type's own body ({@code struct Foo { ...fields... };}).
     *
     * <p>Strategy: scan the writer output tracking brace depth.
     * {@code DataTypeWriter} emits, in dependency order, the forward
     * decls of the requested type and every type it references, then
     * the referenced types' full bodies (only present for by-value
     * members — a pointer needs only a forward decl), and finally the
     * requested type's body LAST. So:
     * <ul>
     *   <li>At depth 0, single-line {@code typedef struct/union/enum
     *       X ...;} lines are kept — they forward-declare the referenced
     *       types (and the requested type itself). This lets a reader
     *       see what {@code Foo}'s fields point at without pulling the
     *       whole dependency graph (that's what {@code with_deps} is
     *       for).</li>
     *   <li>Other types' bodies (dependencies the writer inlined ahead
     *       of ours) are stepped over via brace tracking — NOT emitted.</li>
     *   <li>The requested body is captured from its <code>struct Foo &#123;</code>
     *       header until the matching <code>&#125;;</code> (depth back to 0).</li>
     * </ul>
     *
     * <p>History note on the body header regex: {@code DataTypeWriter}
     * writes the body header as <code>"struct " + name + " &#123;"</code> and
     * APPENDS the composite's GUI description as an inline comment
     * before the EOL — i.e. a struct with a description comes out as
     * <code>struct NAME &#123; /* description *&#47;</code>. An earlier version of
     * this filter anchored <code>\&#123;\s*$</code> (whitespace-only between
     * <code>\&#123;</code> and end-of-line), so it missed any struct carrying a
     * description. That triggered bug #15 (2026-07-20): the "large
     * aggregates" audit couldn't render {@code GameWorld},
     * {@code Town}, the screen classes — exactly the structs that
     * tend to have descriptions set. The fix loosens the anchor to
     * "starts with <code>&lt;kind&gt; &lt;NAME&gt; \&#123;</code>" and lets brace tracking
     * find the matching close; a one-line body (no description, no
     * fields) still works because depth returns to 0 on the same line.
     */
    private static String filterComposite(String raw, String kind, String name) {
        String[] lines = raw.split("\n", -1);
        StringBuilder out = new StringBuilder();
        // Body opener: "struct NAME {" with anything after on the line
        // (the writer commonly appends an inline /* description */).
        // Anchored at start-of-line, then a literal '{' anywhere later
        // on that line — the brace tracker is what finds the close.
        Pattern bodyStart = Pattern.compile(
            "^\\s*" + kind + "\\s+" + Pattern.quote(name) + "\\s*\\{");
        // A single-line forward-declaration typedef, e.g.
        //   typedef struct Town Town, *PTown;
        //   typedef union U U, *PU;
        Pattern fwdTypedef = Pattern.compile(
            "^\\s*typedef\\s+(?:struct|union|enum)\\s+\\S.*;\\s*$");
        int depth = 0;
        boolean capturing = false;
        BraceCounter braces = new BraceCounter();
        for (String line : lines) {
            if (capturing) {
                out.append(line).append('\n');
                depth += braces.delta(line);
                if (depth == 0) break;             // matching `};` of requested body
                continue;
            }
            if (depth == 0 && bodyStart.matcher(line).find()) {
                capturing = true;
                out.append(line).append('\n');
                depth += braces.delta(line);
                if (depth == 0) break;             // single-line body (defensive)
                continue;
            }
            if (depth == 0 && !line.contains("{") && fwdTypedef.matcher(line).matches()) {
                out.append(line).append('\n');     // keep referenced/own forward decls
                continue;
            }
            // Step over other types' bodies (inlined deps) and drop the
            // builtins preamble / blank lines.
            depth += braces.delta(line);
        }
        return out.length() == 0 ? raw : stripTrailingBlank(out);
    }

    /**
     * Counts brace nesting line by line, ignoring braces inside comments.
     * The writer copies descriptions and field comments verbatim into
     * {@code /* ... *&#47;} (or {@code // ...}) comments, and a description
     * such as "see {link}" or one with an unbalanced brace used to end the
     * captured body early or never. A block comment may span lines (a
     * multi-line description), so the state is kept across calls.
     */
    private static final class BraceCounter {
        private boolean inBlockComment;

        /** Net change in brace nesting contributed by one line. */
        int delta(String line) {
            int d = 0;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                char next = i + 1 < line.length() ? line.charAt(i + 1) : '\0';
                if (inBlockComment) {
                    if (c == '*' && next == '/') {
                        inBlockComment = false;
                        i++;
                    }
                } else if (c == '/' && next == '*') {
                    inBlockComment = true;
                    i++;
                } else if (c == '/' && next == '/') {
                    break;
                } else if (c == '{') {
                    d++;
                } else if (c == '}') {
                    d--;
                }
            }
            return d;
        }
    }

    private static String filterEnum(String raw, String name) {
        // typedef enum Foo { ... } Foo;
        // An enum named define_FOO with exactly one value is written as
        //   #define FOO v
        // (no "define_" prefix, no semicolon).
        String[] lines = raw.split("\n", -1);
        String q = Pattern.quote(name);
        Pattern start = Pattern.compile("^\\s*typedef\\s+enum\\s+" + q + "\\s*\\{");
        Pattern end = Pattern.compile("^\\s*\\}\\s*" + q + "\\s*;\\s*$");
        Pattern define = name.startsWith("define_") && name.length() > 7
            ? Pattern.compile("^\\s*#define\\s+" + Pattern.quote(name.substring(7)) + "\\s")
            : null;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (define != null && define.matcher(lines[i]).find()) {
                return lines[i];
            }
            if (!start.matcher(lines[i]).find()) {
                continue;
            }
            // Keep everything up to the matching `} NAME;`.
            for (int j = i; j < lines.length; j++) {
                out.append(lines[j]).append('\n');
                if (end.matcher(lines[j]).matches()) {
                    break;
                }
            }
            break;
        }
        return out.length() == 0 ? raw : stripTrailingBlank(out);
    }

    private static String filterTypedef(String raw, String name) {
        // The writer emits one `typedef ...;` line in which NAME is the
        // identifier being declared. Depending on the base type that is
        //   typedef unsigned int NAME;        plain / pointer (`Foo * NAME;`)
        //   typedef int NAME[4];              array
        //   typedef int (* NAME)(int);        pointer to function
        //   typedef int NAME(int);            function
        // A line where NAME is only the BASE type (`typedef NAME Other;`)
        // must not match, so NAME has to be followed by `;`, `[`, `(` or `)`.
        String[] lines = raw.split("\n", -1);
        Pattern singleTypedef = Pattern.compile(
            "^\\s*typedef\\s.*[\\s*(]" + Pattern.quote(name) + "\\s*(;|\\[.*;|\\(.*;|\\)\\s*\\(.*;)\\s*$");
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
