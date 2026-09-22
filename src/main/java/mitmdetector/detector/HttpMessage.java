package mitmdetector.detector;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The start of an HTTP/1.x request or response: the first line and the headers that fit in the first
 * TCP segment. Nothing is reassembled and the body is never read.
 *
 * <p>Parsed by hand from the raw TCP payload, like {@link DnsMessage} and {@link DhcpMessage}. Anything
 * that does not look like HTTP/1.0 or 1.1 (TLS, HTTP/2, binary data, a segment from the middle of a
 * body) gives {@link Optional#empty()}.
 *
 * @param request     true for a request, false for a response
 * @param method      request method (GET, POST, ...), null for a response
 * @param target      request target as sent, for example "/login?x=1", null for a response
 * @param status      response status code, 0 for a request
 * @param host        value of the Host header in lower case, without port and trailing dot, or null
 * @param location    value of the Location header, or null
 * @param contentType value of the Content-Type header in lower case, or null
 */
public record HttpMessage(boolean request, String method, String target, int status,
                          String host, String location, String contentType) {

    private static final int MAX_INSPECTED_BYTES = 8192;
    private static final Pattern REQUEST_LINE =
            Pattern.compile("^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) (\\S+) HTTP/1\\.[01]$");
    private static final Pattern STATUS_LINE = Pattern.compile("^HTTP/1\\.[01] (\\d{3})(?: .*)?$");
    private static final Pattern LOCATION = Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/:?#]+)");

    /** 301, 302, 303, 307 and 308. */
    public boolean isRedirect() {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /** Any 2xx status. */
    public boolean isSuccess() {
        return status >= 200 && status < 300;
    }

    public boolean isHtml() {
        return contentType != null && contentType.startsWith("text/html");
    }

    /** "http" or "https" (lower case) when Location is an absolute URL, otherwise null. */
    public String locationScheme() {
        Matcher matcher = location == null ? null : LOCATION.matcher(location);
        return matcher != null && matcher.find() ? matcher.group(1).toLowerCase() : null;
    }

    /** Host part of an absolute Location, in lower case and without port, otherwise null. */
    public String locationHost() {
        Matcher matcher = location == null ? null : LOCATION.matcher(location);
        return matcher != null && matcher.find() ? normalizeHost(matcher.group(2)) : null;
    }

    /** Returns the message, or empty when the bytes are not the start of an HTTP/1.x message. */
    public static Optional<HttpMessage> parse(byte[] data) {
        if (data == null || data.length < 12) {
            return Optional.empty();
        }
        int length = Math.min(data.length, MAX_INSPECTED_BYTES);
        String text = new String(data, 0, length, StandardCharsets.ISO_8859_1);

        int firstLineEnd = text.indexOf('\n');
        if (firstLineEnd < 0) {
            return Optional.empty();
        }
        String firstLine = stripCr(text.substring(0, firstLineEnd));

        Map<String, String> headers = new HashMap<>();
        for (String line : text.substring(firstLineEnd + 1).split("\n", -1)) {
            line = stripCr(line);
            if (line.isEmpty()) {
                break;
            }
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.putIfAbsent(line.substring(0, colon).trim().toLowerCase(), line.substring(colon + 1).trim());
            }
        }

        String host = normalizeHost(headers.get("host"));
        String location = headers.get("location");
        String contentType = headers.containsKey("content-type") ? headers.get("content-type").toLowerCase() : null;

        Matcher request = REQUEST_LINE.matcher(firstLine);
        if (request.matches()) {
            return Optional.of(new HttpMessage(true, request.group(1), request.group(2), 0,
                    host, location, contentType));
        }
        Matcher response = STATUS_LINE.matcher(firstLine);
        if (response.matches()) {
            return Optional.of(new HttpMessage(false, null, null, Integer.parseInt(response.group(1)),
                    host, location, contentType));
        }
        return Optional.empty();
    }

    /** Lower case, without port and without a trailing dot. Null or blank gives null. */
    static String normalizeHost(String raw) {
        if (raw == null) {
            return null;
        }
        String host = raw.trim().toLowerCase();
        int colon = host.lastIndexOf(':');
        if (colon >= 0 && host.indexOf(']') < colon) {   // strip ":port", leave IPv6 brackets alone
            host = host.substring(0, colon);
        }
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        return host.isEmpty() ? null : host;
    }

    private static String stripCr(String line) {
        return line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
    }
}
