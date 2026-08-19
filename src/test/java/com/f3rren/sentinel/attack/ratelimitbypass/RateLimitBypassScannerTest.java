package com.f3rren.sentinel.attack.ratelimitbypass;

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
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server, mirroring RateLimitScannerTest's
 * convention.
 */
class RateLimitBypassScannerTest {

    private static final int BURST_SIZE = 5;

    private HttpServer server;
    private String baseUrl;
    private RateLimitBypassScanner scanner;
    private final AtomicInteger noHeaderRequestCount = new AtomicInteger();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/vulnerable", this::vulnerableHandler);
        server.createContext("/immune", this::immuneHandler);
        server.createContext("/never-throttles", this::alwaysOkHandler);
        server.createContext("/write", this::countingHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        scanner = new RateLimitBypassScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000), BURST_SIZE);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsBypassWhenASpoofableHeaderLiftsTheThrottle() {
        Endpoint endpoint = new Endpoint(baseUrl + "/vulnerable", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.RATE_LIMIT_BYPASS);
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        // X-Forwarded-For is the first candidate tried, so it's the one that proves the bypass.
        assertThat(finding.parameter()).isEqualTo("X-Forwarded-For");
        assertThat(finding.payload()).startsWith("203.0.113.");
    }

    @Test
    void doesNotFlagWhenThrottlingIgnoresEveryCandidateHeader() {
        Endpoint endpoint = new Endpoint(baseUrl + "/immune", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void doesNotFlagWhenTheBurstNeverGetsThrottledInTheFirstPlace() {
        // Nothing to bypass: MissingRateLimiting (a different module) is the one that reports
        // this absence.
        Endpoint endpoint = new Endpoint(baseUrl + "/never-throttles", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void ignoresNonGetEndpoints() {
        Endpoint endpoint = new Endpoint(baseUrl + "/write", HttpMethod.POST, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(noHeaderRequestCount.get()).isZero();
    }

    /** Throttles requests carrying none of the candidate headers after 2; any of them bypasses it entirely. */
    private void vulnerableHandler(HttpExchange exchange) throws IOException {
        // com.sun.net.httpserver.Headers is a case-insensitive map, so containsKey (rather than
        // comparing exact keySet() entries) is what actually mirrors HTTP header semantics here.
        boolean hasSpoofableHeader = List.of("X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP").stream()
                .anyMatch(name -> exchange.getRequestHeaders().containsKey(name));
        if (hasSpoofableHeader) {
            writeResponse(exchange, 200);
            return;
        }
        int count = noHeaderRequestCount.incrementAndGet();
        writeResponse(exchange, count <= 2 ? 200 : 429);
    }

    /** Throttles after 2 requests regardless of any header - correctly keyed by the real client. */
    private void immuneHandler(HttpExchange exchange) throws IOException {
        int count = noHeaderRequestCount.incrementAndGet();
        writeResponse(exchange, count <= 2 ? 200 : 429);
    }

    private void alwaysOkHandler(HttpExchange exchange) throws IOException {
        writeResponse(exchange, 200);
    }

    private void countingHandler(HttpExchange exchange) throws IOException {
        noHeaderRequestCount.incrementAndGet();
        writeResponse(exchange, 200);
    }

    private void writeResponse(HttpExchange exchange, int status) throws IOException {
        exchange.sendResponseHeaders(status, -1);
        exchange.close();
    }
}
