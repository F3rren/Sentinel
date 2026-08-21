package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Makes a scan fully hands-off when a target is known upfront (typically set via
 * SENTINEL_SCAN_AUTO_TARGET_URL in a docker-compose deployment): as soon as the app starts, it
 * waits for that target to actually respond - most victim projects have no startup healthcheck
 * of their own, so there's no other way to know it's ready - and then runs the scan without
 * anyone having to call POST /api/scans by hand. The result is still reachable afterwards via
 * GET /api/scans/latest.
 * <p>
 * <b>Fail-on gate.</b> When {@code sentinel.scan.fail-on} names a severity, this turns into a
 * one-shot CI gate: after the auto-scan the process exits with code 0 if no finding reached that
 * severity, or 1 if one did (or if the scan could not run at all - fail closed). The report files
 * are written before the exit, so a pipeline can still collect the JSON/SARIF from the mounted
 * reports directory. Without fail-on the app stays up and serving as usual.
 */
@Component
public class AutoScanRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AutoScanRunner.class);

    private static final Set<String> DISABLED_KEYWORDS = Set.of("OFF", "NONE", "FALSE");

    private final ScanService scanService;
    private final SentinelHttpClient httpClient;
    private final String targetUrl;
    private final int maxAttempts;
    private final long retryDelayMs;
    private final Severity failOn;

    public AutoScanRunner(
            ScanService scanService,
            SentinelHttpClient httpClient,
            @Value("${sentinel.scan.auto-target-url:}") String targetUrl,
            @Value("${sentinel.scan.auto-scan-max-attempts:20}") int maxAttempts,
            @Value("${sentinel.scan.auto-scan-retry-delay-ms:3000}") long retryDelayMs,
            @Value("${sentinel.scan.fail-on:}") String failOnRaw
    ) {
        this.scanService = scanService;
        this.httpClient = httpClient;
        this.targetUrl = targetUrl;
        this.maxAttempts = maxAttempts;
        this.retryDelayMs = retryDelayMs;
        this.failOn = parseFailOn(failOnRaw);
        if (this.failOn == null && failOnRaw != null && !failOnRaw.isBlank()
                && !DISABLED_KEYWORDS.contains(failOnRaw.trim().toUpperCase(Locale.ROOT))) {
            log.warn("Invalid sentinel.scan.fail-on='{}' (expected INFO/LOW/MEDIUM/HIGH/CRITICAL, or OFF): "
                    + "the fail-on gate is disabled.", failOnRaw);
        }
    }

    @Override
    public void run(ApplicationArguments args) {
        if (targetUrl == null || targetUrl.isBlank()) {
            log.info("Auto-scan disabled (sentinel.scan.auto-target-url not set).");
            if (failOn != null) {
                log.warn("sentinel.scan.fail-on is set but sentinel.scan.auto-target-url is not: the "
                        + "fail-on gate only applies to the startup auto-scan and will not run.");
            }
            return;
        }

        String normalizedUrl;
        try {
            normalizedUrl = scanService.normalizeTargetUrl(targetUrl);
        } catch (InvalidTargetException e) {
            log.error("Auto-scan disabled: {}", e.getMessage());
            failClosedIfGated("invalid target url");
            return;
        }

        log.info("Auto-scan enabled for {}: waiting for the target to become reachable...", normalizedUrl);
        if (!waitUntilReachable(normalizedUrl)) {
            log.warn("Target {} unreachable after {} attempts: auto-scan cancelled. "
                    + "You can still start a scan manually via POST /api/scans.", normalizedUrl, maxAttempts);
            failClosedIfGated("target unreachable");
            return;
        }

        log.info("Target {} reachable: starting the automatic scan.", normalizedUrl);
        ScanReport report;
        try {
            report = scanService.runScan(normalizedUrl);
            log.info(report.narrative());
        } catch (Exception e) {
            log.error("Auto-scan failed for {}: {}", normalizedUrl, e.getMessage(), e);
            failClosedIfGated("scan error");
            return;
        }
        applyFailOnGate(report);
    }

    private void applyFailOnGate(ScanReport report) {
        if (failOn == null) {
            return;
        }
        int code = failOnExitCode(report, failOn);
        if (code == 0) {
            log.info("Fail-on gate ({}): PASSED - no finding reached the threshold.", failOn);
        } else {
            log.warn("Fail-on gate ({}): FAILED - at least one finding is at or above the threshold. "
                    + "Exiting with code 1.", failOn);
        }
        exitProcess(code);
    }

    private void failClosedIfGated(String reason) {
        if (failOn == null) {
            return;
        }
        log.warn("Fail-on gate ({}): FAILED - could not complete the scan ({}). Exiting with code 1.",
                failOn, reason);
        exitProcess(1);
    }

    /**
     * 1 if at least one finding is at or above the threshold, 0 otherwise. Uses the per-severity
     * counts rather than {@code overallRisk} (which is INFO even for a clean scan, and would wrongly
     * trip a {@code fail-on=INFO} gate on a report with no findings at all).
     */
    static int failOnExitCode(ScanReport report, Severity failOn) {
        int atOrAboveThreshold = report.summary().countsBySeverity().entrySet().stream()
                .filter(entry -> entry.getKey().ordinal() >= failOn.ordinal())
                .mapToInt(Map.Entry::getValue)
                .sum();
        return atOrAboveThreshold > 0 ? 1 : 0;
    }

    /** OFF/NONE/FALSE/blank -&gt; no gate (null); a valid severity name -&gt; that severity; anything else -&gt; null. */
    static Severity parseFailOn(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().toUpperCase(Locale.ROOT);
        if (DISABLED_KEYWORDS.contains(value)) {
            return null;
        }
        try {
            return Severity.valueOf(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Isolated so a test can capture the intended exit code instead of terminating the JVM. */
    protected void exitProcess(int code) {
        System.exit(code);
    }

    private boolean waitUntilReachable(String normalizedUrl) {
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                httpClient.get(normalizedUrl);
                return true;
            } catch (Exception e) {
                log.debug("Attempt {}/{} failed for {}: {}", attempt, maxAttempts, normalizedUrl, e.getMessage());
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
