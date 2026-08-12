package com.f3rren.sentinel.attack.massassignment;

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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end style tests against a real local HTTP server, mirroring BflaScannerTest's and
 * IdorScannerTest's convention. {@code /aquariums} echoes back whatever JSON body it received
 * (wrapped in {@code {"data": ...}}, matching the enveloped-response shape the recursive search
 * needs to handle), so each test simulates either a vulnerable or a properly bound endpoint by
 * changing what {@link #echoedFields} the handler adds on top of the received body.
 */
class MassAssignmentScannerTest {

    private static final ScanIdentity IDENTITY_A = new ScanIdentity("Authorization", "Bearer tokenA");
    private static final ScanIdentity IDENTITY_B = new ScanIdentity("Authorization", "Bearer tokenB");

    private HttpServer server;
    private String baseUrl;
    private MassAssignmentScanner scanner;

    private final AtomicReference<String> lastReceivedBody = new AtomicReference<>();
    private volatile boolean echoReceivedBody = true;
    private volatile int responseStatus = 201;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/aquariums", this::handleCreate);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        scanner = new MassAssignmentScanner(new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private void handleCreate(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        lastReceivedBody.set(body);
        String responseBody = echoReceivedBody ? "{\"data\":" + body + "}" : "{\"data\":{\"id\":\"1\"}}";
        byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(responseStatus, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private Endpoint createEndpoint(String requestBodySample) {
        return new Endpoint(baseUrl + "/aquariums", HttpMethod.POST, List.of(), requestBodySample);
    }

    @Test
    void doesNothingWhenNoScanHasBegun() {
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(lastReceivedBody.get()).isNull();
    }

    @Test
    void doesNothingWhenScanContextHasNoIdentities() {
        scanner.beginScan(ScanContext.EMPTY);
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(lastReceivedBody.get()).isNull();
    }

    @Test
    void doesNothingForGetEndpoints() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = new Endpoint(baseUrl + "/aquariums", HttpMethod.GET, List.of(), "{\"name\":\"Tank\"}");

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(lastReceivedBody.get()).isNull();
    }

    @Test
    void doesNothingWhenEndpointHasNoRequestBodySample() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = createEndpoint(null);

        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(lastReceivedBody.get()).isNull();
    }

    @Test
    void flagsAnEchoedPrivilegedFieldAsCritical() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).anySatisfy(finding -> {
            assertThat(finding.type()).isEqualTo(VulnerabilityType.MASS_ASSIGNMENT);
            assertThat(finding.parameter()).isEqualTo("role");
            assertThat(finding.severity()).isEqualTo(Severity.CRITICAL);
        });
        assertThat(lastReceivedBody.get()).contains("\"name\":\"Tank\"").contains("\"role\":\"sentinel-");
    }

    @Test
    void flagsAnEchoedOwnershipFieldAsHigh() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).anySatisfy(finding -> {
            assertThat(finding.parameter()).isEqualTo("ownerId");
            assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        });
    }

    @Test
    void reportsOneFindingPerAcceptedField() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        List<Finding> findings = scanner.scan(endpoint);

        // role, isAdmin, ownerId, verified - none already present in the base body.
        assertThat(findings).hasSize(4);
        assertThat(findings).extracting("parameter")
                .containsExactlyInAnyOrder("role", "isAdmin", "ownerId", "verified");
    }

    @Test
    void doesNotFlagWhenTheServerNeverEchoesTheInjectedFields() {
        echoReceivedBody = false;
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        assertThat(scanner.scan(endpoint)).isEmpty();
        // The check still ran (a request was made) - it just found nothing to report.
        assertThat(lastReceivedBody.get()).isNotNull();
    }

    @Test
    void doesNotFlagWhenTheRequestIsRejected() {
        responseStatus = 400;
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        assertThat(scanner.scan(endpoint)).isEmpty();
    }

    @Test
    void skipsAFieldAlreadyDocumentedInTheBaseBody() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        // "role" is already a legitimate, documented property here - injecting over it would
        // prove nothing, so it must not appear among the candidates actually tried.
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\",\"role\":\"member\"}");

        List<Finding> findings = scanner.scan(endpoint);

        assertThat(findings).extracting("parameter").doesNotContain("role");
        assertThat(lastReceivedBody.get()).contains("\"role\":\"member\"");
    }

    @Test
    void usesIdentityBWhenIdentityAIsUnavailable() {
        scanner.beginScan(new ScanContext(null, IDENTITY_B));
        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");

        assertThat(scanner.scan(endpoint)).isNotEmpty();
    }

    @Test
    void resetsStateBetweenScans() {
        scanner.beginScan(new ScanContext(IDENTITY_A, IDENTITY_B));
        scanner.endScan();

        Endpoint endpoint = createEndpoint("{\"name\":\"Tank\"}");
        assertThat(scanner.scan(endpoint)).isEmpty();
        assertThat(lastReceivedBody.get()).isNull();
    }
}
