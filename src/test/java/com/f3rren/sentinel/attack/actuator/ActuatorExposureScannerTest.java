package com.f3rren.sentinel.attack.actuator;

import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
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
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server, mirroring
 * DataExposureScannerTest's convention.
 */
class ActuatorExposureScannerTest {

    private HttpServer server;
    private String baseUrl;
    private ActuatorExposureScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/actuator/env", exchange -> respond(exchange, 200, "application/json", "{\"activeProfiles\":[]}"));
        server.createContext("/actuator/heapdump", exchange -> respond(exchange, 200, "application/octet-stream", "binary-ish content"));
        server.createContext("/actuator/beans", exchange -> respond(exchange, 200, "application/json", "{}"));
        server.createContext("/actuator/configprops", exchange -> respond(exchange, 200, "application/json", "{}"));
        server.createContext("/actuator/threaddump", exchange -> respond(exchange, 200, "application/json", "{}"));
        // Not registered/exposed at all: a real Spring Boot app 404s on an actuator id that
        // isn't in management.endpoints.web.exposure.include.
        server.createContext("/actuator/mappings", exchange -> respond(exchange, 404, "application/json", "{}"));
        server.createContext("/actuator/httpexchanges", exchange -> respond(exchange, 404, "application/json", "{}"));
        // Exposed status-wise, but not actuator-shaped content: simulates an SPA catch-all
        // serving index.html for literally any unknown path - must not be flagged.
        server.createContext("/actuator/loggers", exchange -> respond(exchange, 200, "text/html", "<html>not found</html>"));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new ActuatorExposureScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
        scanner.beginScan(ScanContext.EMPTY);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsExposedSensitiveActuatorEndpointsAndSkipsTheRest() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter")
                .containsExactlyInAnyOrder("env", "heapdump", "beans", "configprops", "threaddump");
        assertThat(findings).allSatisfy(finding -> {
            assertThat(finding.module()).isEqualTo("actuator-exposure");
            assertThat(finding.type()).isEqualTo(VulnerabilityType.EXPOSED_ACTUATOR_ENDPOINT);
            // Response bodies must never leak into the report.
            assertThat(finding.evidence()).doesNotContain("binary-ish content").doesNotContain("activeProfiles");
        });
    }

    @Test
    void assignsCriticalSeverityToEnvAndHeapdump() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings)
                .filteredOn(f -> f.parameter().equals("env") || f.parameter().equals("heapdump"))
                .allSatisfy(finding -> assertThat(finding.severity()).isEqualTo(Severity.CRITICAL));
    }

    @Test
    void doesNotFlagA404NotFoundActuatorId() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter").doesNotContain("mappings", "httpexchanges");
    }

    @Test
    void doesNotFlagA200ResponseThatIsNotActuatorShaped() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter").doesNotContain("loggers");
    }

    @Test
    void onlyProbesOncePerScanRegardlessOfHowManyEndpointsAreSeen() {
        Endpoint first = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());
        Endpoint second = new Endpoint(baseUrl + "/species", HttpMethod.GET, List.of());

        List<Finding> firstFindings = scanner.scan(first);
        List<Finding> secondFindings = scanner.scan(second);

        assertThat(firstFindings).isNotEmpty();
        assertThat(secondFindings).isEmpty();
    }

    @Test
    void probesAgainOnANewScanAfterBeginScanResetsIt() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());
        scanner.scan(endpoint);

        scanner.beginScan(ScanContext.EMPTY);
        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).isNotEmpty();
    }

    private void respond(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
