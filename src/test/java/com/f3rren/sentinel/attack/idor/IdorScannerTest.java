package com.f3rren.sentinel.attack.idor;

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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server, mirroring the other modules'
 * convention. The item context ({@code /aquariums/}) answers based on the caller's
 * {@code Authorization} header: identity A always gets 200 (it created the resource), identity
 * B's status is test-controlled via {@link #itemStatusForIdentityB}, so each test simulates
 * either a vulnerable or a properly protected target without changing the server setup.
 */
class IdorScannerTest {

    private static final ScanIdentity IDENTITY_A = new ScanIdentity("Authorization", "Bearer tokenA");
    private static final ScanIdentity IDENTITY_B = new ScanIdentity("Authorization", "Bearer tokenB");

    private HttpServer server;
    private String baseUrl;
    private IdorScanner scanner;

    private final AtomicInteger createRequestCount = new AtomicInteger();
    private final AtomicInteger itemRequestCount = new AtomicInteger();
    private volatile String lastItemRequestPath;
    private volatile int itemStatusForIdentityB = 200;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/aquariums", exchange -> {
            createRequestCount.incrementAndGet();
            respond(exchange, 201, "{\"success\":true,\"data\":{\"id\":\"42\"}}");
        });
        server.createContext("/aquariums/", exchange -> {
            itemRequestCount.incrementAndGet();
            lastItemRequestPath = exchange.getRequestURI().getPath();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            int status = "Bearer tokenB".equals(auth) ? itemStatusForIdentityB : 200;
            respond(exchange, status, "{}");
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new IdorScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void doesNothingWhenNoScanHasBegun() {
        Endpoint createEndpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of());

        assertThat(scanner.scan(createEndpoint)).isEmpty();
        assertThat(createRequestCount.get()).isZero();
    }

    @Test
    void doesNothingWhenScanContextHasNoIdentities() {
        scanner.beginScan(ScanContext.EMPTY);
        Endpoint createEndpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of());

        assertThat(scanner.scan(createEndpoint)).isEmpty();
        assertThat(createRequestCount.get()).isZero();
    }

    @Test
    void recordsCreatedResourceIdAndRewritesTheGenericSampleIdOnTheItemEndpoint() {
        itemStatusForIdentityB = 403; // secure outcome - this test only cares about id substitution
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));

        List<Finding> createFindings = scanner.scan(new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of()));
        assertThat(createFindings).isEmpty();
        assertThat(createRequestCount.get()).isEqualTo(1);

        // Discovery would have put the generic sample id "1" here - the scanner must rewrite it
        // to the id actually created by identity A (42) before checking identity B. The check
        // itself is deferred: scan() only queues it, endScan() actually resolves it.
        List<Finding> deferred = scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.GET, List.of()));
        assertThat(deferred).isEmpty();
        assertThat(itemRequestCount.get()).isZero();

        List<Finding> itemFindings = scanner.endScan();

        assertThat(itemFindings).isEmpty();
        assertThat(lastItemRequestPath).isEqualTo("/aquariums/42");
    }

    @Test
    void flagsIdorWhenIdentityBCanReadAResourceCreatedByIdentityA() {
        itemStatusForIdentityB = 200; // vulnerable outcome
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.scan(new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of()));
        scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.GET, List.of()));

        List<Finding> findings = scanner.endScan();

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.IDOR);
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.endpointUrl()).isEqualTo(baseUrl + "/aquariums/42");
    }

    @Test
    void flagsIdorEvenWhenTheItemEndpointIsDiscoveredBeforeTheCreateEndpoint() {
        // Common in practice: an OpenAPI spec grouping every /aquariums/{id} operation before
        // /aquariums itself. The item check must still resolve once the create is eventually seen.
        itemStatusForIdentityB = 200; // vulnerable outcome
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.GET, List.of()));
        scanner.scan(new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of()));

        List<Finding> findings = scanner.endScan();

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).endpointUrl()).isEqualTo(baseUrl + "/aquariums/42");
    }

    @Test
    void doesNotFlagWhenIdentityBIsDenied() {
        itemStatusForIdentityB = 403;
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.scan(new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of()));
        scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.GET, List.of()));

        List<Finding> findings = scanner.endScan();

        assertThat(findings).isEmpty();
    }

    @Test
    void flagsMutatingVerbAsCriticalInsteadOfHigh() {
        itemStatusForIdentityB = 200; // vulnerable outcome
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.scan(new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of()));
        scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.DELETE, List.of()));

        List<Finding> findings = scanner.endScan();

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void ignoresNestedResourceCreateEndpoints() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));

        List<Finding> findings = new ArrayList<>(scanner.scan(new Endpoint(baseUrl + "/aquariums/1/tasks", HttpMethod.POST, List.of())));
        findings.addAll(scanner.endScan());

        assertThat(findings).isEmpty();
        assertThat(itemRequestCount.get()).isZero();
        assertThat(createRequestCount.get()).isZero();
    }

    @Test
    void doesNothingForItemEndpointWithoutAPriorCreateInTheSameScan() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));

        List<Finding> deferred = scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.GET, List.of()));
        assertThat(deferred).isEmpty();

        List<Finding> findings = scanner.endScan();

        assertThat(findings).isEmpty();
        assertThat(itemRequestCount.get()).isZero();
    }

    @Test
    void resetsStateBetweenScansSoAnOlderScansCreatedIdIsNeverReused() {
        itemStatusForIdentityB = 200;
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.scan(new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of()));
        scanner.endScan();

        // A brand new scan that never re-creates a resource must not remember the previous
        // scan's id - the module is a singleton bean shared across every scan.
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.scan(new Endpoint(baseUrl + "/aquariums/1", HttpMethod.GET, List.of()));
        List<Finding> findings = scanner.endScan();

        assertThat(findings).isEmpty();
        assertThat(itemRequestCount.get()).isZero();
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes();
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
