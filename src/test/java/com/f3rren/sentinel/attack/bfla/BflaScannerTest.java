package com.f3rren.sentinel.attack.bfla;

import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.ScanIdentity;
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
 * End-to-end style tests against a real local HTTP server, mirroring IdorScannerTest's
 * convention. {@code /admin/resource} answers per-identity via {@link #statusForIdentityA} /
 * {@link #statusForIdentityB}, so each test simulates either a vulnerable or a properly
 * protected endpoint without changing the server setup.
 */
class BflaScannerTest {

    private static final ScanIdentity IDENTITY_A = new ScanIdentity("Authorization", "Bearer tokenA");
    private static final ScanIdentity IDENTITY_B = new ScanIdentity("Authorization", "Bearer tokenB");

    private HttpServer server;
    private String baseUrl;
    private BflaScanner scanner;

    private final AtomicInteger adminRequestCount = new AtomicInteger();
    private volatile int statusForIdentityA = 200;
    private volatile int statusForIdentityB = 200;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        com.sun.net.httpserver.HttpHandler adminHandler = exchange -> {
            adminRequestCount.incrementAndGet();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            int status = "Bearer tokenA".equals(auth) ? statusForIdentityA : statusForIdentityB;
            respond(exchange, status, "{}");
        };
        server.createContext("/admin/resource", adminHandler);
        // Java's built-in HttpServer routes contexts case-sensitively, so the case-insensitivity
        // test below needs its own context registered under the exact casing it requests.
        server.createContext("/ADMIN/resource", adminHandler);
        server.createContext("/products", exchange -> respond(exchange, 200, "{}"));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new BflaScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void doesNothingWhenNoScanHasBegun() {
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(adminRequestCount.get()).isZero();
    }

    @Test
    void doesNothingWhenScanContextHasNoIdentities() {
        scanner.beginScan(ScanContext.EMPTY);
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(adminRequestCount.get()).isZero();
    }

    @Test
    void ignoresEndpointsWithoutAPrivilegedKeywordInThePath() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/products", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(adminRequestCount.get()).isZero();
    }

    @Test
    void flagsAdminEndpointReachableByARegularIdentity() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.BFLA);
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.endpointUrl()).isEqualTo(baseUrl + "/admin/resource");
        assertThat(finding.evidence()).contains("admin");
    }

    @Test
    void doesNotFlagWhenBothIdentitiesAreCorrectlyDenied() {
        statusForIdentityA = 403;
        statusForIdentityB = 403;
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(adminRequestCount.get()).isEqualTo(2);
    }

    @Test
    void triesIdentityBWhenIdentityAIsDenied() {
        statusForIdentityA = 403;
        statusForIdentityB = 200;
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(adminRequestCount.get()).isEqualTo(2);
    }

    @Test
    void stopsAfterIdentityASoOnlyOneFindingIsReportedEvenWhenBothWouldSucceed() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        // Identity A alone already proved it - identity B is never even tried.
        assertThat(adminRequestCount.get()).isEqualTo(1);
    }

    @Test
    void flagsMutatingVerbAsCriticalInsteadOfHigh() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.DELETE, List.of());

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void matchesKeywordCaseInsensitively() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/ADMIN/resource", HttpMethod.GET, List.of());

        assertThat(scanner.scan(endpoint)).hasSize(1);
    }

    @Test
    void resetsStateBetweenScans() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.endScan();

        Endpoint endpoint = new Endpoint(baseUrl + "/admin/resource", HttpMethod.GET, List.of());
        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(adminRequestCount.get()).isZero();
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes();
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
