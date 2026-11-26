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

    private StringQuery() { }

    /** Substring match (or regex when {@code regex} is true). */
    public static Predicate<String> contains(JsonObject req) {
        String query = RpcContext.reqStr(req, "query");
        boolean ignoreCase = RpcContext.reqBool(req, "ignoreCase");
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

    /**
     * Like {@link #contains} but the {@code query} field is OPTIONAL — when
     * missing/empty, returns a predicate that matches every string (used by
     * the merged search/list-defined procedure so an absent query simply means
     * "list all defined strings").
     */
    public static Predicate<String> containsOptional(JsonObject req) {
        String query = RpcContext.optStr(req, "query");
        if (query == null || query.isEmpty()) {
            return s -> true;
        }
        // Forward to contains(); it reads the same fields (query/regex/ignoreCase)
        // and is happy with a non-empty query.
        return contains(req);
    }

    /** Whole-string match (or regex when {@code regex} is true). */
    public static Predicate<String> exact(JsonObject req) {
        String query = RpcContext.reqStr(req, "query");
        boolean ignoreCase = RpcContext.reqBool(req, "ignoreCase");
        Predicate<String> regex = regexOrNull(req, query, ignoreCase);
        if (regex != null) {
            return regex;
        }
        return ignoreCase ? s -> s.equalsIgnoreCase(query) : s -> s.equals(query);
    }

    /**
     * Wall-clock budget for ONE request's regex matching, summed over every
     * candidate string. Matching runs under the server-wide dispatch lock and a
     * {@link java.util.regex.Matcher} cannot be interrupted, so an unbounded
     * client-supplied pattern such as {@code (\w*a?){30}!} would stall every
     * other client indefinitely — without needing the write password.
     */
    static final long REGEX_BUDGET_MS = 10_000;

    /**
     * A {@code find()} predicate for a client-supplied pattern that gives up
     * once the request has spent {@link #REGEX_BUDGET_MS} matching. The input
     * is wrapped in a {@link CharSequence} whose {@code charAt} checks the
     * deadline, which is the only hook the regex engine offers into a running
     * match. The predicate is created per request, so the budget is per request.
     */
    public static Predicate<String> boundedFind(Pattern pattern) {
        long deadline = System.currentTimeMillis() + REGEX_BUDGET_MS;
        return s -> pattern.matcher(new DeadlineCharSequence(s, deadline)).find();
    }

    /** {@link CharSequence} view that aborts regex matching once a deadline passes. */
    private static final class DeadlineCharSequence implements CharSequence {
        private final CharSequence inner;
        private final long deadline;
        private int ticks;

        DeadlineCharSequence(CharSequence inner, long deadline) {
            this.inner = inner;
            this.deadline = deadline;
        }

        @Override
        public char charAt(int index) {
            if ((++ticks & 0xfff) == 0 && System.currentTimeMillis() > deadline) {
                throw new IllegalArgumentException("Regex matching exceeded "
                    + REGEX_BUDGET_MS + " ms; simplify the pattern.");
            }
            return inner.charAt(index);
        }

        @Override
        public int length() {
            return inner.length();
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new DeadlineCharSequence(inner.subSequence(start, end), deadline);
        }

        @Override
        public String toString() {
            return inner.toString();
        }
    }

    /** The regex predicate when {@code regex} is true, else null; throws on a bad pattern. */
    private static Predicate<String> regexOrNull(JsonObject req, String query, boolean ignoreCase) {
        if (!RpcContext.reqBool(req, "regex")) {
            return null;
        }
        try {
            Pattern pattern = Pattern.compile(query, ignoreCase ? Pattern.CASE_INSENSITIVE : 0);
            return boundedFind(pattern);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regex: " + e.getMessage());
        }
    }
}
