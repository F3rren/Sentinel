package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.discovery.EndpointDiscoveryService;
import com.f3rren.sentinel.discovery.openapi.OpenApiDiscoveryResult;
import com.f3rren.sentinel.discovery.openapi.OpenApiDiscoveryService;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.report.ReportFileWriter;
import com.f3rren.sentinel.report.ReportGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanServiceTest {

    @Mock
    private OpenApiDiscoveryService openApiDiscoveryService;

    @Mock
    private EndpointDiscoveryService discoveryService;

    @Mock
    private AttackModule attackModule;

    @Mock
    private ReportFileWriter reportFileWriter;

    private final ReportGenerator reportGenerator = new ReportGenerator();

    private Endpoint getEndpoint;
    private Endpoint postEndpoint;
    private Endpoint deleteEndpoint;

    @BeforeEach
    void setUp() {
        getEndpoint = new Endpoint("http://localhost:8080/search", HttpMethod.GET, List.of(new EndpointParam("q", "test")));
        postEndpoint = new Endpoint("http://localhost:8080/orders", HttpMethod.POST, List.of(new EndpointParam("id", "1")));
        deleteEndpoint = new Endpoint("http://localhost:8080/orders/1", HttpMethod.DELETE, List.of());

        when(discoveryService.discover(any())).thenReturn(List.of());
        // Not every test ends up calling attackModule.scan() (e.g. zero endpoints discovered),
        // so this default stub is legitimately unused in those cases.
        lenient().when(attackModule.scan(any())).thenReturn(List.of());
    }

    @Test
    void onlyAttacksEndpointsWithAllowedHttpMethods() {
        when(openApiDiscoveryService.discover(any())).thenReturn(
                Optional.of(new OpenApiDiscoveryResult("http://localhost:8080/v3/api-docs",
                        List.of(getEndpoint, postEndpoint, deleteEndpoint))));

        ScanService scanService = new ScanService(openApiDiscoveryService, discoveryService,
                List.of(attackModule), reportGenerator, reportFileWriter, 25, "GET");

        ScanReport report = scanService.runScan("http://localhost:8080");

        ArgumentCaptor<Endpoint> attacked = ArgumentCaptor.forClass(Endpoint.class);
        verify(attackModule, times(1)).scan(attacked.capture());
        assertThat(attacked.getValue()).isEqualTo(getEndpoint);
        assertThat(report.endpointsDiscovered()).isEqualTo(3);
        assertThat(report.endpointsTested()).isEqualTo(1);
    }

    @Test
    void attacksEveryEndpointWhenAllMethodsAreAllowedByDefault() {
        when(openApiDiscoveryService.discover(any())).thenReturn(
                Optional.of(new OpenApiDiscoveryResult("http://localhost:8080/v3/api-docs",
                        List.of(getEndpoint, postEndpoint, deleteEndpoint))));

        ScanService scanService = new ScanService(openApiDiscoveryService, discoveryService,
                List.of(attackModule), reportGenerator, reportFileWriter, 25, "GET,POST,PUT,PATCH,DELETE");

        ScanReport report = scanService.runScan("http://localhost:8080");

        verify(attackModule, times(3)).scan(any());
        assertThat(report.endpointsDiscovered()).isEqualTo(3);
        assertThat(report.endpointsTested()).isEqualTo(3);
    }

    @Test
    void fallsBackToDefaultMethodsWhenConfiguredValueHasNoValidEntries() {
        when(openApiDiscoveryService.discover(any())).thenReturn(
                Optional.of(new OpenApiDiscoveryResult("http://localhost:8080/v3/api-docs",
                        List.of(getEndpoint, postEndpoint))));

        ScanService scanService = new ScanService(openApiDiscoveryService, discoveryService,
                List.of(attackModule), reportGenerator, reportFileWriter, 25, "not-a-real-method, also-fake");

        scanService.runScan("http://localhost:8080");

        // Falls back to the full default set, so both endpoints still get attacked.
        verify(attackModule, times(2)).scan(any());
    }

    @Test
    void methodFilterIsAppliedBeforeTheMaxEndpointsCap() {
        List<Endpoint> discovered = new ArrayList<>();
        discovered.add(postEndpoint);
        discovered.add(deleteEndpoint);
        discovered.add(getEndpoint);
        when(openApiDiscoveryService.discover(any())).thenReturn(
                Optional.of(new OpenApiDiscoveryResult("http://localhost:8080/v3/api-docs", discovered)));

        // Cap of 1, but only GET is allowed: the single slot must go to the GET endpoint,
        // not be wasted on whichever endpoint happened to come first in discovery order.
        ScanService scanService = new ScanService(openApiDiscoveryService, discoveryService,
                List.of(attackModule), reportGenerator, reportFileWriter, 1, "GET");

        ScanReport report = scanService.runScan("http://localhost:8080");

        ArgumentCaptor<Endpoint> attacked = ArgumentCaptor.forClass(Endpoint.class);
        verify(attackModule, times(1)).scan(attacked.capture());
        assertThat(attacked.getValue()).isEqualTo(getEndpoint);
        assertThat(report.endpointsTested()).isEqualTo(1);
    }

    @Test
    void getLatestReportReflectsMostRecentScan() {
        when(openApiDiscoveryService.discover(any())).thenReturn(Optional.empty());

        ScanService scanService = new ScanService(openApiDiscoveryService, discoveryService,
                List.of(attackModule), reportGenerator, reportFileWriter, 25, "GET,POST,PUT,PATCH,DELETE");

        // No endpoints discovered at all in this scenario, so the module never actually runs,
        // but the report must still be tracked as "latest" regardless of outcome.
        ScanReport report = scanService.runScan("http://localhost:8080");

        assertThat(scanService.getLatestReport()).isEqualTo(report);
    }
}
