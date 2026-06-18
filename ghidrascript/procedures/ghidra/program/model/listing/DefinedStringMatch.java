package procedures.ghidra.program.model.listing;

/**
 * One defined-string entry. Serialized by gson; null fields omitted.
 *
 * <p>Used by {@link FindStringsHandler} and {@link ListDefinedStringsHandler}.
 */
final class DefinedStringMatch {
    /** Address of the string's first byte (Ghidra "string" representation). */
    final String address;
    /** Decoded string value, no surrounding quotes. May be empty. */
    final String value;
    /** Same as {@code value} but with quotes and C-style escapes (e.g. {@code "hello\n"}). */
    final String representation;
    /** String length in BYTES (matches {@code Data.getLength()}). */
    final int length;
    /** Charset name used to decode the bytes (e.g. {@code "US-ASCII"}, {@code "UTF-16LE"}). */
    final String charset;
    /** DataType name (e.g. {@code "string"}, {@code "unicode"}, {@code "TerminatedCString"}). */
    final String dataType;

    DefinedStringMatch(String address, String value, String representation,
            int length, String charset, String dataType) {
        this.address = address;
        this.value = value;
        this.representation = representation;
        this.length = length;
        this.charset = charset;
        this.dataType = dataType;
    }
}
