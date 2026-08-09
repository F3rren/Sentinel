package com.f3rren.sentinel.attack.ratelimit;

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
 * End-to-end style tests: verifies the module recognizes a target that never throttles a burst
 * of GET requests versus one that does, and that it never bursts a non-GET endpoint at all.
 */
class RateLimitScannerTest {

    private static final int BURST_SIZE = 5;

    private HttpServer server;
    private String baseUrl;
    private RateLimitScanner scanner;
    private final AtomicInteger requestCount = new AtomicInteger();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/never-throttles", this::alwaysOkHandler);
        server.createContext("/throttles", this::throttlesAfterTwoHandler);
        server.createContext("/write", this::countingHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        scanner = new RateLimitScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000), BURST_SIZE);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsMissingRateLimitingWhenTheBurstNeverGetsThrottled() {
        Endpoint endpoint = new Endpoint(baseUrl + "/never-throttles", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.MISSING_RATE_LIMITING);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.LOW);
    }

    @Test
    void doesNotFlagWhenTheTargetThrottlesWithinTheBurst() {
        Endpoint endpoint = new Endpoint(baseUrl + "/throttles", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).isEmpty();
    }

    @Test
    void ignoresNonGetEndpoints() {
        Endpoint endpoint = new Endpoint(baseUrl + "/write", HttpMethod.POST, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).isEmpty();
        assertThat(requestCount.get()).isZero();
    }

    private void alwaysOkHandler(HttpExchange exchange) throws IOException {
        writeResponse(exchange, 200);
    }

    private void throttlesAfterTwoHandler(HttpExchange exchange) throws IOException {
        int count = requestCount.incrementAndGet();
        writeResponse(exchange, count <= 2 ? 200 : 429);
    }

    private void countingHandler(HttpExchange exchange) throws IOException {
        requestCount.incrementAndGet();
        writeResponse(exchange, 200);
    }

    private void writeResponse(HttpExchange exchange, int status) throws IOException {
        exchange.sendResponseHeaders(status, -1);
        exchange.close();
    }
}
