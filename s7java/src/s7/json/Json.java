// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.json;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader and writer (RFC 8259), standard library only.
 *
 * <p>Objects read as {@code LinkedHashMap<String, Object>} (member order kept, duplicate
 * names refused), arrays as {@code List<Object>}, strings as {@code String}, true/false
 * as {@code Boolean}, null as {@link #NULL}. A number without a fraction or exponent
 * reads as {@code Long}, or {@code BigInteger} beyond 64 bits; any other number reads
 * as {@code Double}. This mirrors how Boost.JSON and Python's json module tell integers
 * from reals, which the S7 schemas rely on ("3" is an integer, "3.0" is not).
 */
public final class Json {
    /** JSON null, distinct from an absent member. */
    public static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    private final String text;
    private int position;

    private Json(String text) {
        this.text = text;
    }

    public static Object parse(String text) {
        Json reader = new Json(text);
        reader.skipWhitespace();
        Object value = reader.value(0);
        reader.skipWhitespace();
        if (reader.position != text.length()) {
            throw reader.error("trailing characters");
        }
        return value;
    }

    private static final int MAX_DEPTH = 256;

    private Object value(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("nested too deeply");
        }
        if (position >= text.length()) {
            throw error("unexpected end");
        }
        char c = text.charAt(position);
        switch (c) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"':
                return string();
            case 't':
                return literal("true", Boolean.TRUE);
            case 'f':
                return literal("false", Boolean.FALSE);
            case 'n':
                return literal("null", NULL);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return number();
                }
                throw error("unexpected character '" + c + "'");
        }
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> members = new LinkedHashMap<>();
        position++;
        skipWhitespace();
        if (peek('}')) {
            position++;
            return members;
        }
        while (true) {
            skipWhitespace();
            if (!peek('"')) {
                throw error("expected a member name");
            }
            String name = string();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            if (members.containsKey(name)) {
                throw error("duplicate member '" + name + "'");
            }
            members.put(name, value(depth + 1));
            skipWhitespace();
            if (peek(',')) {
                position++;
                continue;
            }
            expect('}');
            return members;
        }
    }

    private List<Object> array(int depth) {
        List<Object> items = new ArrayList<>();
        position++;
        skipWhitespace();
        if (peek(']')) {
            position++;
            return items;
        }
        while (true) {
            skipWhitespace();
            items.add(value(depth + 1));
            skipWhitespace();
            if (peek(',')) {
                position++;
                continue;
            }
            expect(']');
            return items;
        }
    }

    private String string() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            if (position >= text.length()) {
                throw error("unterminated string");
            }
            char c = text.charAt(position++);
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20) {
                throw error("control character in a string");
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (position >= text.length()) {
                throw error("unterminated escape");
            }
            char e = text.charAt(position++);
            switch (e) {
                case '"', '\\', '/' -> out.append(e);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (position + 4 > text.length()) {
                        throw error("truncated \\u escape");
                    }
                    try {
                        out.append((char) Integer.parseInt(text.substring(position, position + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw error("bad \\u escape");
                    }
                    position += 4;
                }
                default -> throw error("bad escape '\\" + e + "'");
            }
        }
    }

    private Object number() {
        int start = position;
        if (peek('-')) {
            position++;
        }
        if (peek('0')) {
            position++;
        } else if (position < text.length() && Character.isDigit(text.charAt(position))) {
            digits();
        } else {
            throw error("bad number");
        }
        boolean integer = true;
        if (peek('.')) {
            integer = false;
            position++;
            if (!(position < text.length() && Character.isDigit(text.charAt(position)))) {
                throw error("bad number");
            }
            digits();
        }
        if (peek('e') || peek('E')) {
            integer = false;
            position++;
            if (peek('+') || peek('-')) {
                position++;
            }
            if (!(position < text.length() && Character.isDigit(text.charAt(position)))) {
                throw error("bad number");
            }
            digits();
        }
        String literal = text.substring(start, position);
        if (!integer) {
            return Double.parseDouble(literal); // correctly rounded, like Boost.JSON's precise mode and Python
        }
        BigInteger value = new BigInteger(literal);
        return value.bitLength() < 64 ? (Object) value.longValue() : value;
    }

    private void digits() {
        while (position < text.length() && Character.isDigit(text.charAt(position))) {
            position++;
        }
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, position)) {
            throw error("bad literal");
        }
        position += word.length();
        return value;
    }

    private boolean peek(char c) {
        return position < text.length() && text.charAt(position) == c;
    }

    private void expect(char c) {
        if (!peek(c)) {
            throw error("expected '" + c + "'");
        }
        position++;
    }

    private void skipWhitespace() {
        while (position < text.length()) {
            char c = text.charAt(position);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            position++;
        }
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("JSON: " + message + " at offset " + position);
    }

    // ---- writing ----------------------------------------------------------------------

    /** Compact JSON. Doubles are written with Java's shortest round-trip form. */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(Object value, StringBuilder out) {
        if (value == null || value == NULL) {
            out.append("null");
        } else if (value instanceof String s) {
            quote(s, out);
        } else if (value instanceof Boolean || value instanceof Long || value instanceof Integer || value instanceof BigInteger) {
            out.append(value);
        } else if (value instanceof Double d) {
            if (d.isNaN() || d.isInfinite()) {
                throw new IllegalArgumentException("JSON cannot hold " + d);
            }
            out.append(d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString(d.longValue()) + ".0" : d.toString());
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> member : ((Map<String, Object>) map).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                quote(member.getKey(), out);
                out.append(':');
                write(member.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof List<?> list) {
            out.append('[');
            for (int index = 0; index < list.size(); index++) {
                if (index > 0) {
                    out.append(',');
                }
                write(list.get(index), out);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("not a JSON value: " + value.getClass());
        }
    }

    public static void quote(String s, StringBuilder out) {
        out.append('"');
        for (int index = 0; index < s.length(); index++) {
            char c = s.charAt(index);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
