package com.f3rren.sentinel.attack.xss;

import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server: verifies the reflected-payload
 * detection itself, and the split between an exploitable HTML-context finding and a merely
 * unsafe (but not directly exploitable via this response) JSON-context finding.
 */
class XssScannerTest {

    private HttpServer server;
    private String baseUrl;
    private XssScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/reflect-html", exchange -> reflectHandler(exchange, "text/html"));
        server.createContext("/reflect-json", exchange -> reflectHandler(exchange, "application/json"));
        server.createContext("/reflect-no-content-type", exchange -> reflectHandler(exchange, null));
        server.createContext("/encoded", this::encodedHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new XssScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsReflectedPayloadInHtmlResponseAsHighSeverity() {
        Endpoint endpoint = new Endpoint(baseUrl + "/reflect-html", HttpMethod.GET, List.of(new EndpointParam("q", "test")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.REFLECTED_XSS);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(findings.get(0).parameter()).isEqualTo("q");
    }

    @Test
    void flagsReflectedPayloadWithoutContentTypeAsHighSeverity() {
        Endpoint endpoint = new Endpoint(baseUrl + "/reflect-no-content-type", HttpMethod.GET, List.of(new EndpointParam("q", "test")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.REFLECTED_XSS);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void downgradesReflectedPayloadInJsonResponseToLowSeverity() {
        Endpoint endpoint = new Endpoint(baseUrl + "/reflect-json", HttpMethod.GET, List.of(new EndpointParam("q", "test")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.UNSANITIZED_INPUT_REFLECTION);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.LOW);
    }

    @Test
    void doesNotFlagWhenPayloadIsHtmlEncoded() {
        Endpoint endpoint = new Endpoint(baseUrl + "/encoded", HttpMethod.GET, List.of(new EndpointParam("q", "test")));

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void doesNothingWhenEndpointHasNoParams() {
        Endpoint endpoint = new Endpoint(baseUrl + "/reflect-html", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    private void reflectHandler(HttpExchange exchange, String contentType) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String reflected = query.getOrDefault("q", "");
        if (contentType != null) {
            exchange.getResponseHeaders().add("Content-Type", contentType);
        }
        byte[] body = reflected.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.getResponseBody().close();
    }

    private void encodedHandler(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String reflected = query.getOrDefault("q", "")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
        exchange.getResponseHeaders().add("Content-Type", "text/html");
        byte[] body = reflected.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.getResponseBody().close();
    }

    private Map<String, String> parseQuery(URI uri) {
        Map<String, String> params = new java.util.LinkedHashMap<>();
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            String[] parts = pair.split("=", 2);
            String key = java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            params.put(key, value);
        }
        return params;
    }
}
