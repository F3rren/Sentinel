package com.f3rren.sentinel.attack.sensitivefile;

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
 * ActuatorExposureScannerTest's convention.
 */
class SensitiveFileExposureScannerTest {

    private HttpServer server;
    private String baseUrl;
    private SensitiveFileExposureScanner scanner;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/.git/HEAD", exchange -> respond(exchange, 200, "ref: refs/heads/main\n"));
        server.createContext("/.git/config", exchange -> respond(exchange, 200,
                "[core]\n\trepositoryformatversion = 0\n"));
        server.createContext("/.env", exchange -> respond(exchange, 200,
                "DB_PASSWORD=hunter2\nJWT_SECRET=changeme\n"));
        server.createContext("/.env.local", exchange -> respond(exchange, 404, "not found"));
        server.createContext("/id_rsa", exchange -> respond(exchange, 200,
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\n"));
        server.createContext("/docker-compose.yml", exchange -> respond(exchange, 200,
                "version: \"3\"\nservices:\n  app:\n    image: app\n"));
        server.createContext("/backup.sql", exchange -> respond(exchange, 200,
                "-- MySQL dump 10.13\nCREATE TABLE users (id INT);\n"));
        // Exposed status-wise, but not the real file: a catch-all that answers 200 with an
        // unrelated HTML page for literally any unknown path - must not be flagged.
        server.createContext("/web.config", exchange -> respond(exchange, 200, "<html>not found</html>"));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new SensitiveFileExposureScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
        scanner.beginScan(ScanContext.EMPTY);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void flagsExposedSensitiveFilesAndSkipsTheRest() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter")
                .containsExactlyInAnyOrder(".git/HEAD", ".git/config", ".env", "id_rsa", "docker-compose.yml", "backup.sql");
        assertThat(findings).allSatisfy(finding -> {
            assertThat(finding.module()).isEqualTo("sensitive-file-exposure");
            assertThat(finding.type()).isEqualTo(VulnerabilityType.EXPOSED_SENSITIVE_FILE);
            // Response bodies must never leak into the report.
            assertThat(finding.evidence()).doesNotContain("hunter2").doesNotContain("changeme");
        });
    }

    @Test
    void assignsCriticalSeverityToGitAndCredentialFiles() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings)
                .filteredOn(f -> List.of(".git/HEAD", ".git/config", ".env", "id_rsa").contains(f.parameter()))
                .allSatisfy(finding -> assertThat(finding.severity()).isEqualTo(Severity.CRITICAL));
    }

    @Test
    void doesNotFlagA404NotFoundFile() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter").doesNotContain(".env.local");
    }

    @Test
    void doesNotFlagA200ResponseThatDoesNotMatchTheExpectedContent() {
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter").doesNotContain("web.config");
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

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
