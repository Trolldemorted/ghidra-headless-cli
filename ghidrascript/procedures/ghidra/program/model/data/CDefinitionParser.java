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

        CParser parser = new CParser(dtm);
        parser.setParseFileName("cdtm-snippet.c");
        DataType parsed;
        try {
            parsed = parser.parse(snippet);
        } catch (ParseException pe) {
            throw new IllegalArgumentException("C parse error: " + pe.getMessage());
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

    /**
     * Detect "anonymous definition" form: leading {@code struct}, {@code union},
     * or {@code enum} keyword followed (after optional whitespace) by {@code {}
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
