package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
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
        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "", 3, 1);

        runner.run(null);

        verifyNoInteractions(httpClient);
        verify(scanService, never()).runScan(anyString());
    }

    @Test
    void doesNothingWhenTargetUrlIsInvalid() throws Exception {
        when(scanService.normalizeTargetUrl("not a url")).thenThrow(new InvalidTargetException("bad target"));

        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "not a url", 3, 1);
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

        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "localhost:9090", 5, 1);
        runner.run(null);

        verify(httpClient, times(3)).get("http://localhost:9090");
        verify(scanService).runScan("http://localhost:9090");
    }

    @Test
    void givesUpAfterMaxAttemptsWithoutScanning() throws Exception {
        when(scanService.normalizeTargetUrl("localhost:9090")).thenReturn("http://localhost:9090");
        when(httpClient.get("http://localhost:9090")).thenThrow(new IOException("connection refused"));

        AutoScanRunner runner = new AutoScanRunner(scanService, httpClient, "localhost:9090", 3, 1);
        runner.run(null);

        verify(httpClient, times(3)).get("http://localhost:9090");
        verify(scanService, never()).runScan(anyString());
    }

    private ScanReport fakeReport() {
        Instant now = Instant.now();
        return new ScanReport("id", "http://localhost:9090", now, now, 10, 0, 0, null,
                List.of(), new ScanSummary(0, Map.of(Severity.INFO, 0), Severity.INFO),
                "Investigazione su http://localhost:9090 completata. Nessuna vulnerabilità rilevata.");
    }
}
