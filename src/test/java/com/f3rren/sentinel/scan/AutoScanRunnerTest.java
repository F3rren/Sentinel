package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AutoScanRunnerTest {

    @Mock
    private ScanService scanService;

    @Mock
    private SentinelHttpClient httpClient;

    @Test
    void doesNothingWhenTargetUrlIsBlank() throws Exception {
        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "", 3, 1, "");

        runner.run(null);

        verifyNoInteractions(httpClient);
        verify(scanService, never()).runScan(anyString());
    }

    @Test
    void doesNothingWhenTargetUrlIsInvalid() throws Exception {
        when(scanService.normalizeTargetUrl("not a url")).thenThrow(new InvalidTargetException("bad target"));

        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "not a url", 3, 1, "");
        runner.run(null);

        verifyNoInteractions(httpClient);
        verify(scanService, never()).runScan(anyString());
    }

    @Test
    void scansAsSoonAsTargetBecomesReachable() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090"))
                .thenThrow(new IOException("connection refused"))
                .thenThrow(new IOException("connection refused"))
                .thenReturn(new HttpResponseData(200, "ok", 1));
        when(scanService.runScan("http://localhost:9090")).thenReturn(fakeReport());

        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "localhost:9090", 5, 1, "");
        runner.run(null);

        verify(httpClient, times(3)).get("http://localhost:9090");
        verify(scanService).runScan("http://localhost:9090");
    }

    @Test
    void givesUpAfterMaxAttemptsWithoutScanning() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090")).thenThrow(new IOException("connection refused"));

        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "localhost:9090", 3, 1, "");
        runner.run(null);

        verify(httpClient, times(3)).get("http://localhost:9090");
        verify(scanService, never()).runScan(anyString());
    }

    // ── fail-on gate: pure decision ────────────────────────────────────────────────────

    @Test
    void failOnExitCodeIsOneWhenAFindingReachesTheThreshold() {
        ScanReport report = reportWith(Map.of(Severity.HIGH, 1, Severity.LOW, 3));

        assertThat(AutoScanRunner.failOnExitCode(report, Severity.HIGH)).isEqualTo(1);
        assertThat(AutoScanRunner.failOnExitCode(report, Severity.LOW)).isEqualTo(1);
    }

    @Test
    void failOnExitCodeIsZeroWhenEveryFindingIsBelowTheThreshold() {
        ScanReport report = reportWith(Map.of(Severity.HIGH, 2, Severity.LOW, 5));

        // HIGH findings exist, but the threshold is CRITICAL - nothing reaches it.
        assertThat(AutoScanRunner.failOnExitCode(report, Severity.CRITICAL)).isEqualTo(0);
    }

    @Test
    void failOnExitCodeIsZeroForACleanReportEvenAtTheLowestThreshold() {
        ScanReport report = reportWith(Map.of(Severity.INFO, 0, Severity.LOW, 0));

        assertThat(AutoScanRunner.failOnExitCode(report, Severity.INFO)).isEqualTo(0);
    }

    @Test
    void parseFailOnMapsKeywordsAndSeverities() {
        assertThat(AutoScanRunner.parseFailOn("HIGH")).isEqualTo(Severity.HIGH);
        assertThat(AutoScanRunner.parseFailOn("critical")).isEqualTo(Severity.CRITICAL);
        assertThat(AutoScanRunner.parseFailOn("")).isNull();
        assertThat(AutoScanRunner.parseFailOn(null)).isNull();
        assertThat(AutoScanRunner.parseFailOn("OFF")).isNull();
        assertThat(AutoScanRunner.parseFailOn("bogus")).isNull();
    }

    // ── fail-on gate: wiring (exit captured, JVM not terminated) ────────────────────────

    @Test
    void exitsWithOneWhenTheGateFails() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090")).thenReturn(new HttpResponseData(200, "ok", 1));
        when(scanService.runScan("http://localhost:9090")).thenReturn(reportWith(Map.of(Severity.HIGH, 1)));

        AutoScanRunner runner = spy(new AutoScanRunner(scanService, httpClient, "localhost:9090", 3, 1, "HIGH"));
        doNothing().when(runner).exitProcess(anyInt());

        runner.run(null);

        verify(runner).exitProcess(1);
    }

    @Test
    void exitsWithZeroWhenTheGatePasses() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090")).thenReturn(new HttpResponseData(200, "ok", 1));
        when(scanService.runScan("http://localhost:9090")).thenReturn(reportWith(Map.of(Severity.LOW, 4)));

        AutoScanRunner runner = spy(new AutoScanRunner(scanService, httpClient, "localhost:9090", 3, 1, "HIGH"));
        doNothing().when(runner).exitProcess(anyInt());

        runner.run(null);

        verify(runner).exitProcess(0);
    }

    @Test
    void failsClosedWhenTheTargetIsUnreachableAndGated() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090")).thenThrow(new IOException("connection refused"));

        AutoScanRunner runner = spy(new AutoScanRunner(scanService, httpClient, "localhost:9090", 2, 1, "HIGH"));
        doNothing().when(runner).exitProcess(anyInt());

        runner.run(null);

        verify(scanService, never()).runScan(anyString());
        verify(runner).exitProcess(1);
    }

    @Test
    void doesNotExitWhenFailOnIsOff() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090")).thenReturn(new HttpResponseData(200, "ok", 1));
        when(scanService.runScan("http://localhost:9090")).thenReturn(reportWith(Map.of(Severity.CRITICAL, 2)));

        AutoScanRunner runner = spy(new AutoScanRunner(scanService, httpClient, "localhost:9090", 3, 1, ""));

        runner.run(null);

        verify(runner, never()).exitProcess(anyInt());
    }

    private ScanReport reportWith(Map<Severity, Integer> countsBySeverity) {
        int total = countsBySeverity.values().stream().mapToInt(Integer::intValue).sum();
        ScanSummary summary = new ScanSummary(total, countsBySeverity, Map.of(), Severity.INFO, 0, false);
        Instant now = Instant.now();
        return new ScanReport("id", "http://localhost:9090", now, now, 0, 0, 0, null,
                List.of(), summary, "narrative");
    }

    private ScanReport fakeReport() {
        Instant now = Instant.now();
        return new ScanReport("id", "http://localhost:9090", now, now, 10, 0, 0, null,
                List.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Map.of(VulnerabilityType.SQL_INJECTION_ERROR_BASED, 0), Severity.INFO, 0, false),
                "Investigation of http://localhost:9090 completed. No vulnerabilities detected.");
    }
}
