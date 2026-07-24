package com.f3rren.sentinel.web;

import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
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
                List.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Severity.INFO),
                "Investigazione su http://localhost:8080 completata in 42 ms. Nessuna vulnerabilità rilevata.");
        when(scanService.runScan(eq("localhost:8080"))).thenReturn(report);

        mockMvc.perform(post("/api/scans")
                        .contentType("application/json")
                        .content("{\"targetUrl\":\"localhost:8080\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("scan-1"))
                .andExpect(jsonPath("$.targetUrl").value("http://localhost:8080"));
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
        when(scanService.runScan(anyString())).thenThrow(new InvalidTargetException("targetUrl non valido"));

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
                List.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Severity.INFO),
                "Investigazione su http://api-gateway:8080 completata in 3,6 secondi. Nessuna vulnerabilità rilevata.");
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
