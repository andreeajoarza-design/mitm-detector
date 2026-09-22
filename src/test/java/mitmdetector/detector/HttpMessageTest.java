package mitmdetector.detector;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static mitmdetector.detector.HttpTestPackets.bytes;

class HttpMessageTest {

    @Test
    void parsesRequestAndNormalizesHost() {
        HttpMessage message = HttpMessage.parse(
                bytes("GET /login?next=/a HTTP/1.1\r\nHOST: Shop.Example.NET.:80\r\nAccept: */*\r\n\r\n")).orElseThrow();
        assertTrue(message.request());
        assertEquals("GET", message.method());
        assertEquals("/login?next=/a", message.target());
        assertEquals("shop.example.net", message.host());
    }

    @Test
    void parsesRedirectWithAbsoluteLocation() {
        HttpMessage message = HttpMessage.parse(
                bytes("HTTP/1.1 301 Moved Permanently\r\nLocation: HTTPS://Shop.Example.net:443/x\r\n\r\n")).orElseThrow();
        assertFalse(message.request());
        assertEquals(301, message.status());
        assertTrue(message.isRedirect());
        assertEquals("https", message.locationScheme());
        assertEquals("shop.example.net", message.locationHost());
    }

    @Test
    void relativeLocationHasNoSchemeOrHost() {
        HttpMessage message = HttpMessage.parse(
                bytes("HTTP/1.1 302 Found\r\nLocation: /other\r\n\r\n")).orElseThrow();
        assertNull(message.locationScheme());
        assertNull(message.locationHost());
    }

    @Test
    void parsesContentType() {
        HttpMessage message = HttpMessage.parse(
                bytes("HTTP/1.1 200 OK\r\nContent-Type: Text/HTML; charset=utf-8\r\n\r\n<html>")).orElseThrow();
        assertTrue(message.isSuccess());
        assertTrue(message.isHtml());
        HttpMessage image = HttpMessage.parse(bytes("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n")).orElseThrow();
        assertFalse(image.isHtml());
    }

    @Test
    void headersAfterTheBlankLineBelongToTheBody() {
        HttpMessage message = HttpMessage.parse(
                bytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nContent-Type: text/html\r\n")).orElseThrow();
        assertFalse(message.isHtml());
    }

    @Test
    void acceptsBareLineFeeds() {
        HttpMessage message = HttpMessage.parse(bytes("GET / HTTP/1.0\nHost: a.example\n\n")).orElseThrow();
        assertEquals("a.example", message.host());
    }

    @Test
    void rejectsNonHttp() {
        assertEquals(Optional.empty(), HttpMessage.parse(null));
        assertEquals(Optional.empty(), HttpMessage.parse(new byte[]{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, (byte) 0xfc, 0x03, 0x03, 0x00}));
        assertEquals(Optional.empty(), HttpMessage.parse(bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")));
        assertEquals(Optional.empty(), HttpMessage.parse(bytes("just some text in the middle of a body\r\n")));
        assertEquals(Optional.empty(), HttpMessage.parse(bytes("HTTP/1.1 20 OK\r\n\r\n")));
    }

    @Test
    void rejectsFirstLineThatIsNotFinished() {
        assertEquals(Optional.empty(), HttpMessage.parse(bytes("GET /some/long/path HTTP/1.1")));
    }
}
