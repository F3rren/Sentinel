package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Makes a scan fully hands-off when a target is known upfront (typically set via
 * SENTINEL_SCAN_AUTO_TARGET_URL in a docker-compose deployment): as soon as the app starts, it
 * waits for that target to actually respond - most victim projects have no startup healthcheck
 * of their own, so there's no other way to know it's ready - and then runs the scan without
 * anyone having to call POST /api/scans by hand. The result is still reachable afterwards via
 * GET /api/scans/latest.
 */
@Component
public class AutoScanRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AutoScanRunner.class);

    private final ScanService scanService;
    private final SentinelHttpClient httpClient;
    private final String targetUrl;
    private final int maxAttempts;
    private final long retryDelayMs;

    public AutoScanRunner(
            ScanService scanService,
            SentinelHttpClient httpClient,
            @Value("${sentinel.scan.auto-target-url:}") String targetUrl,
            @Value("${sentinel.scan.auto-scan-max-attempts:20}") int maxAttempts,
            @Value("${sentinel.scan.auto-scan-retry-delay-ms:3000}") long retryDelayMs
    ) {
        this.scanService = scanService;
        this.httpClient = httpClient;
        this.targetUrl = targetUrl;
        this.maxAttempts = maxAttempts;
        this.retryDelayMs = retryDelayMs;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (targetUrl == null || targetUrl.isBlank()) {
            log.info("Auto-scan disabilitato (sentinel.scan.auto-target-url non impostata).");
            return;
        }

        String normalizedUrl;
        try {
            normalizedUrl = scanService.normalizeTargetUrl(targetUrl);
        } catch (InvalidTargetException e) {
            log.error("Auto-scan disabilitato: {}", e.getMessage());
            return;
        }

        log.info("Auto-scan abilitato per {}: attendo che il target sia raggiungibile...", normalizedUrl);
        if (!waitUntilReachable(normalizedUrl)) {
            log.warn("Target {} non raggiungibile dopo {} tentativi: auto-scan annullato. "
                    + "Puoi comunque avviare una scansione manualmente via POST /api/scans.", normalizedUrl, maxAttempts);
            return;
        }

        log.info("Target {} raggiungibile: avvio la scansione automatica.", normalizedUrl);
        try {
            ScanReport report = scanService.runScan(normalizedUrl);
            log.info(report.narrative());
        } catch (Exception e) {
            log.error("Auto-scan fallito per {}: {}", normalizedUrl, e.getMessage(), e);
        }
    }

    private boolean waitUntilReachable(String normalizedUrl) {
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                httpClient.get(normalizedUrl);
                return true;
            } catch (Exception e) {
                log.debug("Tentativo {}/{} fallito per {}: {}", attempt, maxAttempts, normalizedUrl, e.getMessage());
                sleep(retryDelayMs);
            }
        }
        return false;
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
