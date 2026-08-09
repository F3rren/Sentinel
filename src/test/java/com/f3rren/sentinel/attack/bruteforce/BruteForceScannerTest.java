package com.f3rren.sentinel.attack.bruteforce;

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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server: verifies the module only engages
 * endpoints shaped like a login (JSON body or form/query params with both a username- and a
 * password-like field), correctly reads a successful login among the tried credential pairs,
 * and distinguishes "never throttled" from "throttled" when deciding whether to report missing
 * brute-force protection.
 */
class BruteForceScannerTest {

    private HttpServer server;
    private String baseUrl;
    private BruteForceScanner scanner;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AtomicInteger requestCount = new AtomicInteger();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/login", this::loginHandler);
        server.createContext("/login-never-blocks", this::alwaysRejectHandler);
        server.createContext("/login-rate-limited", this::rateLimitedAfterFewHandler);
        server.createContext("/login-form", this::formLoginHandler);
        server.createContext("/not-a-login", this::countingHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        scanner = new BruteForceScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000), 8);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsWeakCredentialsWhenALoginEndpointAcceptsACommonPassword() {
        Endpoint endpoint = new Endpoint(baseUrl + "/login", HttpMethod.POST, List.of(),
                "{\"username\":\"placeholder\",\"password\":\"placeholder\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.WEAK_CREDENTIALS);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.CRITICAL);
        assertThat(findings.get(0).payload()).isEqualTo("admin / admin");
    }

    @Test
    void reportsMissingBruteForceProtectionWhenNeverThrottled() {
        Endpoint endpoint = new Endpoint(baseUrl + "/login-never-blocks", HttpMethod.POST, List.of(),
                "{\"username\":\"placeholder\",\"password\":\"placeholder\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.MISSING_BRUTE_FORCE_PROTECTION);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.LOW);
    }

    @Test
    void doesNotReportMissingProtectionWhenTheTargetStartsThrottling() {
        Endpoint endpoint = new Endpoint(baseUrl + "/login-rate-limited", HttpMethod.POST, List.of(),
                "{\"username\":\"placeholder\",\"password\":\"placeholder\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).isEmpty();
    }

    @Test
    void ignoresEndpointsThatAreNotShapedLikeALogin() {
        Endpoint getEndpoint = new Endpoint(baseUrl + "/not-a-login", HttpMethod.GET, List.of());
        Endpoint noCredentialFields = new Endpoint(baseUrl + "/not-a-login", HttpMethod.POST, List.of(),
                "{\"name\":\"placeholder\"}");

        assertThat(scanner.scan(getEndpoint)).isEmpty();
        assertThat(scanner.scan(noCredentialFields)).isEmpty();
        // Neither case should even reach the server: the login-shape check must gate before
        // spending a single request.
        assertThat(requestCount.get()).isZero();
    }

    @Test
    void detectsALoginShapeFromFormParametersWhenThereIsNoJsonBody() {
        Endpoint endpoint = new Endpoint(baseUrl + "/login-form", HttpMethod.POST,
                List.of(new EndpointParam("username", "placeholder"), new EndpointParam("password", "placeholder")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.WEAK_CREDENTIALS);
    }

    private void loginHandler(HttpExchange exchange) throws IOException {
        JsonNode body = readJsonBody(exchange);
        boolean valid = "admin".equals(body.path("username").asText()) && "admin".equals(body.path("password").asText());
        writeResponse(exchange, valid ? 200 : 401, valid ? "{\"token\":\"abc\"}" : "{\"error\":\"invalid\"}");
    }

    private void alwaysRejectHandler(HttpExchange exchange) throws IOException {
        writeResponse(exchange, 401, "{\"error\":\"invalid\"}");
    }

    private void rateLimitedAfterFewHandler(HttpExchange exchange) throws IOException {
        int count = requestCount.incrementAndGet();
        // First few requests (baseline included) get a normal rejection, then the target starts
        // throttling - mirrors a real rate limiter kicking in mid-scan.
        writeResponse(exchange, count <= 3 ? 401 : 429, "{}");
    }

    private void formLoginHandler(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        boolean valid = body.contains("username=admin") && body.contains("password=admin");
        writeResponse(exchange, valid ? 200 : 401, valid ? "{\"token\":\"abc\"}" : "{\"error\":\"invalid\"}");
    }

    private void countingHandler(HttpExchange exchange) throws IOException {
        requestCount.incrementAndGet();
        writeResponse(exchange, 200, "{}");
    }

    private JsonNode readJsonBody(HttpExchange exchange) throws IOException {
        byte[] bytes = exchange.getRequestBody().readAllBytes();
        return objectMapper.readTree(bytes.length == 0 ? "{}" : new String(bytes, StandardCharsets.UTF_8));
    }

    private void writeResponse(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
