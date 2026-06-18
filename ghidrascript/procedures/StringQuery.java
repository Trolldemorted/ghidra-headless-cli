package procedures;

import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.JsonObject;

/**
 * Builds a string matcher from a request's {@code query} / {@code regex} /
 * {@code ignoreCase} fields, shared by the function-search procedures.
 *
 * The plain (non-regex) semantics differ by use: {@link #contains} matches a substring
 * (name search), while {@link #exact} matches the whole string (tag search — "the function
 * has this tag", not "a tag containing this text"). When {@code regex} is true both use
 * {@link java.util.regex.Matcher#find()} (matches anywhere; anchor with {@code ^...$} for a
 * full-string match). {@code ignoreCase} applies to whichever mode is in effect.
 */
public final class StringQuery {

    private StringQuery() {}

    /** Substring match (or regex when {@code regex} is true). */
    public static Predicate<String> contains(JsonObject req) {
        String query = RpcContext.reqStr(req, "query");
        boolean ignoreCase = RpcContext.optBool(req, "ignoreCase", false);
        Predicate<String> regex = regexOrNull(req, query, ignoreCase);
        if (regex != null) {
            return regex;
        }
        if (ignoreCase) {
            String needle = query.toLowerCase();
            return s -> s.toLowerCase().contains(needle);
        }
        return s -> s.contains(query);
    }

    /** Whole-string match (or regex when {@code regex} is true). */
    public static Predicate<String> exact(JsonObject req) {
        String query = RpcContext.reqStr(req, "query");
        boolean ignoreCase = RpcContext.optBool(req, "ignoreCase", false);
        Predicate<String> regex = regexOrNull(req, query, ignoreCase);
        if (regex != null) {
            return regex;
        }
        return ignoreCase ? s -> s.equalsIgnoreCase(query) : s -> s.equals(query);
    }

    /** The regex predicate when {@code regex} is true, else null; throws on a bad pattern. */
    private static Predicate<String> regexOrNull(JsonObject req, String query, boolean ignoreCase) {
        if (!RpcContext.optBool(req, "regex", false)) {
            return null;
        }
        try {
            Pattern pattern = Pattern.compile(query, ignoreCase ? Pattern.CASE_INSENSITIVE : 0);
            return s -> pattern.matcher(s).find();
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regex: " + e.getMessage());
        }
    }
}
