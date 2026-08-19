package com.f3rren.sentinel.attack.errordisclosure;

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
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server, mirroring XssScannerTest's convention.
 */
class VerboseErrorDisclosureScannerTest {

    private static final String CHAOS_VALUE = "99999999999999999999999999999999999999";

    private HttpServer server;
    private String baseUrl;
    private VerboseErrorDisclosureScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/stack-trace", exchange -> respondIfChaosPresent(exchange,
                "java.lang.NumberFormatException: For input string: \"" + CHAOS_VALUE + "\"\n"
                        + "\tat java.base/java.lang.NumberFormatException.forInputString(NumberFormatException.java:67)\n"
                        + "\tat com.example.service.AquariumService.parse(AquariumService.java:42)\n"));
        server.createContext("/caused-by", exchange -> respondIfChaosPresent(exchange,
                "{\"error\":\"internal\"}\nCaused by: java.lang.ArithmeticException: overflow\n"));
        server.createContext("/exception-name", exchange -> respondIfChaosPresent(exchange,
                "{\"message\":\"it.f3rren.aquarium.service.QuantityException: value out of range\"}"));
        server.createContext("/clean", exchange -> respondIfChaosPresent(exchange, "{\"error\":\"Invalid request\"}"));
        server.createContext("/throttled", exchange -> respond(exchange, 429, "{\"error\":\"Too Many Requests\"}"));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new VerboseErrorDisclosureScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsAJavaStackTraceFrameAsHighSeverity() {
        Endpoint endpoint = new Endpoint(baseUrl + "/stack-trace", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.VERBOSE_ERROR_DISCLOSURE);
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.parameter()).isEqualTo("id");
        assertThat(finding.payload()).isEqualTo(CHAOS_VALUE);
        // The matched stack-trace text itself must never leak into the report.
        assertThat(finding.evidence()).doesNotContain("AquariumService.java:42");
    }

    @Test
    void flagsACausedByMarkerAsHighSeverity() {
        Endpoint endpoint = new Endpoint(baseUrl + "/caused-by", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void flagsAFullyQualifiedExceptionNameAsMediumSeverity() {
        Endpoint endpoint = new Endpoint(baseUrl + "/exception-name", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void doesNotFlagACleanErrorResponse() {
        Endpoint endpoint = new Endpoint(baseUrl + "/clean", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void doesNotFlagAThrottledResponse() {
        Endpoint endpoint = new Endpoint(baseUrl + "/throttled", HttpMethod.GET, List.of(new EndpointParam("id", "1")));

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void fuzzesTheRequestBodyWithChaosValuesWhenASampleIsPresent() {
        Endpoint endpoint = new Endpoint(baseUrl + "/stack-trace", HttpMethod.POST, List.of(),
                "{\"name\":\"Reef Tank\",\"ownerId\":5}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).parameter()).isEqualTo("(request body)");
    }

    @Test
    void doesNothingForABodyEndpointWithNoSample() {
        Endpoint endpoint = new Endpoint(baseUrl + "/clean", HttpMethod.POST, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    private void respondIfChaosPresent(HttpExchange exchange, String stackTraceBody) throws IOException {
        String query = exchange.getRequestURI().getRawQuery();
        String requestBody = new String(readAll(exchange.getRequestBody()), StandardCharsets.UTF_8);
        boolean hasChaos = (query != null && query.contains(CHAOS_VALUE)) || requestBody.contains(CHAOS_VALUE);
        if (hasChaos) {
            respond(exchange, 500, stackTraceBody);
        } else {
            respond(exchange, 200, "{\"ok\":true}");
        }
    }

    private byte[] readAll(InputStream in) throws IOException {
        return in.readAllBytes();
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
