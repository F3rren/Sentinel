package com.f3rren.sentinel.attack.authn;

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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server: verifies the module reads status
 * codes correctly (2xx = finding, 401/403 = protected, everything else = inconclusive) and
 * picks severity from the HTTP verb.
 */
class MissingAuthenticationScannerTest {

    private HttpServer server;
    private String baseUrl;
    private MissingAuthenticationScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/open-read", exchange -> respond(exchange, 200));
        server.createContext("/open-write", exchange -> respond(exchange, 201));
        server.createContext("/protected-401", exchange -> respond(exchange, 401));
        server.createContext("/protected-403", exchange -> respond(exchange, 403));
        server.createContext("/inconclusive", exchange -> respond(exchange, 415));
        server.createContext("/requires-json-body", this::requiresJsonBodyHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new MissingAuthenticationScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsGetEndpointRespondingWithoutCredentialsAsMedium() {
        Endpoint endpoint = new Endpoint(baseUrl + "/open-read", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).type()).isEqualTo(VulnerabilityType.MISSING_AUTHENTICATION);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void flagsMutatingEndpointRespondingWithoutCredentialsAsHigh() {
        Endpoint endpoint = new Endpoint(baseUrl + "/open-write", HttpMethod.POST, List.of(new EndpointParam("name", "test")));

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void doesNotFlagEndpointThatReturns401() {
        Endpoint endpoint = new Endpoint(baseUrl + "/protected-401", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void doesNotFlagEndpointThatReturns403() {
        Endpoint endpoint = new Endpoint(baseUrl + "/protected-403", HttpMethod.DELETE, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void treatsOtherStatusCodesAsInconclusive() {
        Endpoint endpoint = new Endpoint(baseUrl + "/inconclusive", HttpMethod.POST, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void withoutARequestBodySampleAnEndpointRequiringJsonIsInconclusive() {
        Endpoint endpoint = new Endpoint(baseUrl + "/requires-json-body", HttpMethod.POST, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void aRequestBodySampleLetsTheSameEndpointBeFlagged() {
        Endpoint endpoint = new Endpoint(baseUrl + "/requires-json-body", HttpMethod.POST, List.of(),
                "{\"name\":\"test\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    private void requiresJsonBodyHandler(HttpExchange exchange) throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        byte[] requestBody = exchange.getRequestBody().readAllBytes();
        boolean hasJsonBody = "application/json".equals(contentType) && requestBody.length > 0;
        respond(exchange, hasJsonBody ? 201 : 415);
    }

    private void respond(HttpExchange exchange, int status) throws IOException {
        byte[] body = "{}".getBytes();
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.getResponseBody().close();
    }
}
