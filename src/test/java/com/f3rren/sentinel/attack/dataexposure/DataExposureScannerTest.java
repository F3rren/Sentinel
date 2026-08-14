package com.f3rren.sentinel.attack.dataexposure;

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
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server, mirroring
 * SecurityMisconfigurationScannerTest's convention: each context returns a fixed JSON body,
 * verifying the recursive field-name search fires (and stays silent) correctly.
 */
class DataExposureScannerTest {

    private HttpServer server;
    private String baseUrl;
    private DataExposureScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/clean", exchange -> respond(exchange, 200,
                "{\"id\":1,\"name\":\"Reef Tank\",\"nextPageToken\":\"abc123\"}"));
        server.createContext("/leaky", exchange -> respond(exchange, 200,
                "{\"id\":1,\"username\":\"alice\",\"password\":\"hunter2\"}"));
        server.createContext("/nested", exchange -> respond(exchange, 200,
                "{\"data\":{\"user\":{\"id\":1,\"passwordHash\":\"$2a$10$abc\"}}}"));
        server.createContext("/array", exchange -> respond(exchange, 200,
                "{\"data\":[{\"id\":1,\"secret_key\":\"sk_live_abc\"},{\"id\":2,\"name\":\"ok\"}]}"));
        server.createContext("/financial", exchange -> respond(exchange, 200,
                "{\"cardNumber\":\"4111111111111111\",\"cvv\":\"123\"}"));
        server.createContext("/not-found", exchange -> respond(exchange, 404, "{}"));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new DataExposureScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void reportsNothingWhenResponseHasNoSensitiveLookingFields() {
        // Also covers that a generic "token" field (nextPageToken here) never matches: "token"
        // is deliberately excluded from the keyword list - too many legitimate matches
        // (pagination cursors, CSRF tokens issued to the caller) to be a reliable signal.
        Endpoint endpoint = new Endpoint(baseUrl + "/clean", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void flagsAPasswordFieldAsCritical() {
        Endpoint endpoint = new Endpoint(baseUrl + "/leaky", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE);
        assertThat(finding.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(finding.parameter()).isEqualTo("password");
        // The actual leaked value must never appear anywhere in the finding.
        assertThat(finding.evidence()).doesNotContain("hunter2");
        assertThat(finding.description()).doesNotContain("hunter2");
    }

    @Test
    void matchesFieldNamesCaseAndSeparatorInsensitively() {
        Endpoint endpoint = new Endpoint(baseUrl + "/nested", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).parameter()).isEqualTo("data.user.passwordHash");
    }

    @Test
    void recursesIntoArrays() {
        Endpoint endpoint = new Endpoint(baseUrl + "/array", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).parameter()).isEqualTo("data[0].secret_key");
        assertThat(findings.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void flagsFinancialFieldsAsHighNotCritical() {
        Endpoint endpoint = new Endpoint(baseUrl + "/financial", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(2);
        assertThat(findings).allSatisfy(finding -> assertThat(finding.severity()).isEqualTo(Severity.HIGH));
        assertThat(findings).extracting("parameter").containsExactlyInAnyOrder("cardNumber", "cvv");
    }

    @Test
    void skipsNonGetEndpoints() {
        Endpoint endpoint = new Endpoint(baseUrl + "/leaky", HttpMethod.POST, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void skipsNonSuccessfulResponses() {
        Endpoint endpoint = new Endpoint(baseUrl + "/not-found", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
