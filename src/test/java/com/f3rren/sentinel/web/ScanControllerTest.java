package com.f3rren.sentinel.web;

import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.ScanIdentity;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import com.f3rren.sentinel.scan.ScanService;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import com.f3rren.sentinel.web.exception.ScanNotFoundException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ScanController.class)
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private ScanService scanService;

    @Test
    void startScanReturnsCreatedReport() throws Exception {
        ScanReport report = new ScanReport(
                "scan-1", "http://localhost:8080", Instant.now(), Instant.now(), 42, 3, 3, null,
                List.of(), Map.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Map.of(VulnerabilityType.SQL_INJECTION_ERROR_BASED, 0), Severity.INFO, 0, false),
                "Investigation of http://localhost:8080 completed in 42 ms. No vulnerabilities detected.");
        when(scanService.runScan(eq("localhost:8080"), eq(ScanContext.EMPTY))).thenReturn(report);

        mockMvc.perform(post("/api/scans")
                        .contentType("application/json")
                        .content("{\"targetUrl\":\"localhost:8080\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("scan-1"))
                .andExpect(jsonPath("$.targetUrl").value("http://localhost:8080"));
    }

    @Test
    void startScanWithIdentitiesPassesThemThroughAsScanContext() throws Exception {
        ScanReport report = new ScanReport(
                "scan-2", "http://localhost:8080", Instant.now(), Instant.now(), 42, 3, 3, null,
                List.of(), Map.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Map.of(VulnerabilityType.SQL_INJECTION_ERROR_BASED, 0), Severity.INFO, 0, false),
                "Investigation of http://localhost:8080 completed in 42 ms. No vulnerabilities detected.");
        ScanContext expectedContext = new ScanContext(
                new ScanIdentity("Authorization", "Bearer tokenA"),
                new ScanIdentity("Authorization", "Bearer tokenB"));
        when(scanService.runScan(eq("localhost:8080"), eq(expectedContext))).thenReturn(report);

        mockMvc.perform(post("/api/scans")
                        .contentType("application/json")
                        .content("{\"targetUrl\":\"localhost:8080\",\"identities\":{"
                                + "\"a\":{\"header\":\"Authorization\",\"value\":\"Bearer tokenA\"},"
                                + "\"b\":{\"header\":\"Authorization\",\"value\":\"Bearer tokenB\"}}}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("scan-2"));
    }

    @Test
    void startScanRejectsBlankTargetUrl() throws Exception {
        mockMvc.perform(post("/api/scans")
                        .contentType("application/json")
                        .content("{\"targetUrl\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("validation_error"));
    }

    @Test
    void startScanRejectsInvalidTarget() throws Exception {
        when(scanService.runScan(anyString(), any(ScanContext.class))).thenThrow(new InvalidTargetException("Invalid targetUrl"));

        mockMvc.perform(post("/api/scans")
                        .contentType("application/json")
                        .content("{\"targetUrl\":\"not a url\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_target"));
    }

    @Test
    void getScanReturnsNotFoundForUnknownId() throws Exception {
        when(scanService.getReport("missing")).thenThrow(new ScanNotFoundException("missing"));

        mockMvc.perform(get("/api/scans/missing"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("scan_not_found"));
    }

    @Test
    void getLatestScanReturnsMostRecentReport() throws Exception {
        ScanReport report = new ScanReport(
                "scan-auto", "http://api-gateway:8080", Instant.now(), Instant.now(), 3646, 46, 46,
                "http://api-gateway:8080/v3/api-docs/swagger-config",
                List.of(), Map.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Map.of(VulnerabilityType.SQL_INJECTION_ERROR_BASED, 0), Severity.INFO, 0, false),
                "Investigation of http://api-gateway:8080 completed in 3.6 seconds. No vulnerabilities detected.");
        when(scanService.getLatestReport()).thenReturn(report);

        mockMvc.perform(get("/api/scans/latest"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("scan-auto"));
    }

    @Test
    void getLatestScanReturnsNotFoundWhenNoScanRanYet() throws Exception {
        when(scanService.getLatestReport()).thenThrow(new ScanNotFoundException("latest"));

        mockMvc.perform(get("/api/scans/latest"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("scan_not_found"));
    }
}
