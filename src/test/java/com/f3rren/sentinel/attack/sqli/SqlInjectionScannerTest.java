package com.f3rren.sentinel.attack.sqli;

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
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests: a tiny local HTTP server simulates a vulnerable / safe backend and
 * the real SentinelHttpClient + SqlInjectionScanner are exercised against it.
 */
class SqlInjectionScannerTest {

    private HttpServer server;
    private String baseUrl;
    private SqlInjectionScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/vulnerable", this::errorBasedHandler);
        server.createContext("/blind", this::booleanBasedHandler);
        server.createContext("/safe", this::safeHandler);
        server.createContext("/rate-limited", this::rateLimitedHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        SentinelHttpClient httpClient = new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000);
        scanner = new SqlInjectionScanner(httpClient);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void detectsErrorBasedSqlInjection() {
        Endpoint endpoint = new Endpoint(baseUrl + "/vulnerable", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.SQL_INJECTION_ERROR_BASED);
        assertThat(finding.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(finding.parameter()).isEqualTo("id");
        assertThat(finding.evidence()).containsIgnoringCase("mysql");
    }

    @Test
    void detectsBooleanBasedSqlInjection() {
        Endpoint endpoint = new Endpoint(baseUrl + "/blind", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.SQL_INJECTION_BOOLEAN_BASED);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void doesNotFlagBooleanBasedSqliWhenTheFalseConditionIsRateLimited() {
        // Reproduces a real false positive: baseline and the true-condition payload both get
        // 200, but by the time the false-condition payload is sent (the 11th request to this
        // same endpoint+param - baseline, 8 error-based payloads, then the true payload), a
        // rate limiter kicks in and returns 429. The differing status/body used to read as a
        // SQLi signal even though it's purely a byproduct of Sentinel's own request volume.
        Endpoint endpoint = new Endpoint(baseUrl + "/rate-limited", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).isEmpty();
    }

    @Test
    void reportsNoFindingsForSafeEndpoint() {
        Endpoint endpoint = new Endpoint(baseUrl + "/safe", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).isEmpty();
    }

    private void errorBasedHandler(HttpExchange exchange) throws IOException {
        String id = queryParam(exchange, "id");
        boolean triggersError = id != null && (id.contains("'") || id.contains("\""));
        String body = triggersError
                ? "Warning: mysqli_fetch_array(): You have an error in your SQL syntax; "
                        + "check the manual that corresponds to your MySQL server version"
                : "<html><body>OK</body></html>";
        writeResponse(exchange, triggersError ? 500 : 200, body);
    }

    private void booleanBasedHandler(HttpExchange exchange) throws IOException {
        String id = queryParam(exchange, "id");
        boolean falseCondition = "' AND '1'='2' -- ".equals(id);
        String body = falseCondition
                ? "<html><body>No results</body></html>"
                : "<html><body>" + "Row found. ".repeat(60) + "</body></html>";
        writeResponse(exchange, 200, body);
    }

    private void safeHandler(HttpExchange exchange) throws IOException {
        writeResponse(exchange, 200, "<html><body>Nothing interesting here.</body></html>");
    }

    private void rateLimitedHandler(HttpExchange exchange) throws IOException {
        String id = queryParam(exchange, "id");
        boolean falseCondition = "' AND '1'='2' -- ".equals(id);
        writeResponse(exchange, falseCondition ? 429 : 200, "<html><body>OK</body></html>");
    }

    private String queryParam(HttpExchange exchange, String name) {
        String query = exchange.getRequestURI().getRawQuery();
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            if (key.equals(name)) {
                return kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            }
        }
        return null;
    }

    private void writeResponse(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
