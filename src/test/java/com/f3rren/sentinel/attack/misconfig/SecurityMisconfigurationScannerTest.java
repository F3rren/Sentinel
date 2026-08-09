package com.f3rren.sentinel.attack.misconfig;

import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server: verifies each of the three
 * independent checks (missing headers, permissive CORS, server banner) fires and stays silent
 * correctly, and that non-GET/non-2xx endpoints are skipped entirely.
 */
class SecurityMisconfigurationScannerTest {

    private HttpServer server;
    private String baseUrl;
    private SecurityMisconfigurationScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/secure", exchange -> respond(exchange, 200, true, null, null));
        server.createContext("/missing-headers", exchange -> respond(exchange, 200, false, null, null));
        server.createContext("/cors-wildcard", exchange -> respond(exchange, 200, true, "*", null));
        server.createContext("/cors-reflect-credentials", this::corsReflectCredentialsHandler);
        server.createContext("/banner", exchange -> respond(exchange, 200, true, null, "Apache/2.4.41"));
        server.createContext("/not-found", exchange -> respond(exchange, 404, false, null, null));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new SecurityMisconfigurationScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void reportsNothingWhenHeadersAndCorsAreProperlyConfigured() {
        Endpoint endpoint = new Endpoint(baseUrl + "/secure", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void flagsMissingSecurityHeaders() {
        Endpoint endpoint = new Endpoint(baseUrl + "/missing-headers", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.MISSING_SECURITY_HEADERS);
        assertThat(finding.severity()).isEqualTo(Severity.LOW);
        assertThat(finding.evidence())
                .contains("X-Content-Type-Options")
                .contains("X-Frame-Options")
                .contains("Content-Security-Policy");
        // Target is plain HTTP, not HTTPS: HSTS wouldn't apply even if configured, so it must
        // not be listed as a gap here.
        assertThat(finding.evidence()).doesNotContain("Strict-Transport-Security");
    }

    @Test
    void flagsWildcardCorsAsMedium() {
        Endpoint endpoint = new Endpoint(baseUrl + "/cors-wildcard", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.PERMISSIVE_CORS);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void flagsReflectedOriginWithCredentialsAsHigh() {
        Endpoint endpoint = new Endpoint(baseUrl + "/cors-reflect-credentials", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.PERMISSIVE_CORS);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void flagsVersionedServerBanner() {
        Endpoint endpoint = new Endpoint(baseUrl + "/banner", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.SERVER_BANNER_DISCLOSURE);
        assertThat(findings.get(0).evidence()).contains("Apache/2.4.41");
    }

    @Test
    void skipsNonGetEndpoints() {
        Endpoint endpoint = new Endpoint(baseUrl + "/missing-headers", HttpMethod.POST, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void skipsNonSuccessfulResponses() {
        Endpoint endpoint = new Endpoint(baseUrl + "/not-found", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    private void corsReflectCredentialsHandler(HttpExchange exchange) throws IOException {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (origin != null) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", origin);
            exchange.getResponseHeaders().add("Access-Control-Allow-Credentials", "true");
        }
        respond(exchange, 200, true, null, null);
    }

    private void respond(HttpExchange exchange, int status, boolean withSecurityHeaders, String corsAllowOrigin,
                          String serverBanner) throws IOException {
        if (withSecurityHeaders) {
            exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
            exchange.getResponseHeaders().add("X-Frame-Options", "DENY");
            exchange.getResponseHeaders().add("Content-Security-Policy", "default-src 'none'");
        }
        if (corsAllowOrigin != null) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", corsAllowOrigin);
        }
        if (serverBanner != null) {
            exchange.getResponseHeaders().add("Server", serverBanner);
        }
        byte[] body = "{}".getBytes();
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.getResponseBody().close();
    }
}
