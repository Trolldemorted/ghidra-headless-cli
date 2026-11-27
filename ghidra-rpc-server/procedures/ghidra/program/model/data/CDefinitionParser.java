package procedures.ghidra.program.model.data;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

/**
 * Parse a single named C snippet ("{@code struct Foo { int x; };}") into a
 * {@link DataType} ready to be added to the program's DTM.
 *
 * The snippet is parsed directly into the program DTM. {@link CParser} adds
 * the parsed types to its destination, so by the time we return the type is
 * already known to the DTM — callers just resolve the conflict (create: add;
 * edit: replace the existing entry by name). Built-in primitives resolve via
 * the DTM's open archives; no separate {@code StandAloneDataTypeManager} is
 * needed because we WANT the type added.
 *
 * <p>Mirrors the pyghidra idiom:
 * <pre>
 *     parser = CParser(dtm)
 *     parsed = parser.parse(snippet)
 *     dtm.addDataType(parsed, DataTypeConflictHandler.REPLACE_HANDLER)
 * </pre>
 *
 * <p><b>Named snippets only.</b> Ghidra's {@code CParser} does not register
 * anonymous composites/enums in its parsed-types maps, so {@code parser.parse}
 * returns {@code null} for "struct { int x; };" (no name to bind). We surface
 * that as {@link IllegalArgumentException} — callers must put a name in the
 * snippet itself.
 */
final class CDefinitionParser {

    /**
     * Parse one C snippet and return the single named {@link DataType} it
     * produces. Throws {@link IllegalArgumentException} on parse failure,
     * no types, anonymous types, or multiple types — callers expect exactly
     * one named type.
     */
    static DataType parse(String snippet, DataTypeManager dtm)
            throws IllegalArgumentException {
        if (snippet == null || snippet.trim().isEmpty()) {
            throw new IllegalArgumentException("C definition is empty.");
        }
        if (isAnonymous(snippet)) {
            throw new IllegalArgumentException(
                "C snippet must define a NAMED type. Got an anonymous "
                + "struct/union/enum body — write e.g. "
                + "`struct Foo { int x; };` with an identifier.");
        }

        checkBounds(snippet);

        CParser parser = new CParser(dtm);
        parser.setParseFileName("cdtm-snippet.c");
        DataType parsed;
        try {
            parsed = parser.parse(snippet);
        } catch (ParseException pe) {
            throw new IllegalArgumentException("C parse error: " + pe.getMessage());
        } catch (StackOverflowError so) {
            throw new IllegalArgumentException("C parse error: definition is nested too deeply.");
        } catch (Error e) {
            // JavaCC reports lexical errors as TokenMgrError (an Error, not an
            // Exception); CParser rethrows it as-is.
            if (e instanceof OutOfMemoryError) {
                throw e;
            }
            throw new IllegalArgumentException("C parse error: " + e.getMessage());
        }
        if (parsed == null) {
            String msgs = parser.getParseMessages();
            throw new IllegalArgumentException("C parse failed: "
                + (msgs != null && !msgs.isEmpty() ? msgs.trim() : "unknown error"));
        }
        if (parsed.getName() == null || parsed.getName().isEmpty()) {
            throw new IllegalArgumentException(
                "C snippet must define a NAMED type (parsed result has no name).");
        }
        return parsed;
    }

    /** Longest accepted snippet. Real type definitions are far smaller. */
    static final int MAX_SNIPPET_CHARS = 256 * 1024;
    /** Deepest accepted parenthesis nesting (function-pointer types need 2-3). */
    static final int MAX_PAREN_DEPTH = 8;
    /** Deepest accepted brace/bracket nesting. */
    static final int MAX_BLOCK_DEPTH = 64;

    /**
     * Reject input that makes Ghidra's CParser run away. The generated parser
     * backtracks exponentially on nested parentheses — measured on 12.1.2:
     * 20 levels = 4 s, 24 levels = 57 s, x4 per two more — it cannot be
     * cancelled or interrupted, and it runs under the server-wide dispatch
     * lock. Deep brace nesting overflows the stack instead.
     */
    private static void checkBounds(String snippet) {
        if (snippet.length() > MAX_SNIPPET_CHARS) {
            throw new IllegalArgumentException("C definition is too long (" + snippet.length()
                + " chars; limit " + MAX_SNIPPET_CHARS + ").");
        }
        int paren = 0;
        int block = 0;
        for (int i = 0; i < snippet.length(); i++) {
            char c = snippet.charAt(i);
            if (c == '(') {
                if (++paren > MAX_PAREN_DEPTH) {
                    throw new IllegalArgumentException("C definition nests parentheses deeper "
                        + "than " + MAX_PAREN_DEPTH + " levels.");
                }
            } else if (c == ')') {
                paren = Math.max(0, paren - 1);
            } else if (c == '{' || c == '[') {
                if (++block > MAX_BLOCK_DEPTH) {
                    throw new IllegalArgumentException("C definition nests braces/brackets "
                        + "deeper than " + MAX_BLOCK_DEPTH + " levels.");
                }
            } else if (c == '}' || c == ']') {
                block = Math.max(0, block - 1);
            }
        }
    }

    /**
     * Detect "anonymous definition" form: leading {@code struct}, {@code union},
     * or {@code enum} keyword followed (after optional whitespace) by <code>&#123;</code>
     * or {@code ;}. We reject this form outright because Ghidra's {@code CParser}
     * handles anonymous types inconsistently — sometimes returning the last
     * field's type, sometimes auto-naming to {@code enum_1} — neither of which
     * is what the caller wants.
     */
    private static boolean isAnonymous(String snippet) {
        String trimmed = snippet.stripLeading();
        for (String kw : new String[] { "struct", "union", "enum" }) {
            if (!trimmed.startsWith(kw)) continue;
            int i = kw.length();
            while (i < trimmed.length() && Character.isWhitespace(trimmed.charAt(i))) i++;
            if (i >= trimmed.length()) continue;
            char c = trimmed.charAt(i);
            // Anonymous if next non-WS char is `{` (body) or `;` (declaration
            // with no name). Already-named if it's a letter/digit/underscore.
            return c == '{' || c == ';';
        }
        return false;
    }
}
