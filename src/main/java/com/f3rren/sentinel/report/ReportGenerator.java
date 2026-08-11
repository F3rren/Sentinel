package com.f3rren.sentinel.report;

import com.f3rren.sentinel.http.RequestStats;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.FindingGroup;
import com.f3rren.sentinel.model.FindingOccurrence;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Aggregates raw findings into a report with per-severity and per-type counts, a single
 * qualitative risk rating, and a numeric risk score, plus a plain-language narrative
 * summarizing all of that - useful when the report is read directly (e.g. printed from curl)
 * instead of consumed by another program.
 * <p>
 * The qualitative {@code overallRisk} (highest severity seen) and the numeric
 * {@code riskScore} answer different questions: a single CRITICAL finding and twenty CRITICAL
 * findings both report {@code overallRisk = CRITICAL}, but the score - a simple weighted sum,
 * not a formal methodology like CVSS - differentiates volume, so a scan can be compared to an
 * earlier one on the same target and not just labelled with a single severity tier.
 */
@Component
public class ReportGenerator {

    private static final Map<Severity, Integer> SEVERITY_WEIGHTS = Map.of(
            Severity.INFO, 0,
            Severity.LOW, 3,
            Severity.MEDIUM, 8,
            Severity.HIGH, 20,
            Severity.CRITICAL, 40
    );

    // Below this many requests, a handful of 429s could just be noise (a couple of endpoints
    // genuinely rate-limited on purpose) rather than the target throttling the whole scan - not
    // worth a caveat on a report that barely made any requests to begin with.
    private static final int MIN_REQUESTS_FOR_RATE_LIMIT_CHECK = 10;
    // Above this fraction of throttled responses, treat the scan as compromised enough that
    // findings elsewhere in the report can't be trusted at face value.
    private static final double RATE_LIMIT_THROTTLE_RATIO_THRESHOLD = 0.15;

    public ScanReport buildReport(String id, String targetUrl, Instant startedAt, Instant finishedAt,
                                   int endpointsDiscovered, int endpointsTested, String openApiSpecUrl,
                                   List<Finding> findings, RequestStats requestStats) {
        boolean possiblyRateLimited = requestStats.total() >= MIN_REQUESTS_FOR_RATE_LIMIT_CHECK
                && requestStats.throttledRatio() >= RATE_LIMIT_THROTTLE_RATIO_THRESHOLD;
        ScanSummary summary = summarize(findings, possiblyRateLimited);
        List<FindingGroup> groupedFindings = groupFindings(findings);
        long durationMillis = Duration.between(startedAt, finishedAt).toMillis();
        String narrative = buildNarrative(targetUrl, durationMillis, endpointsDiscovered, endpointsTested,
                openApiSpecUrl, summary, requestStats);
        return new ScanReport(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered, endpointsTested,
                openApiSpecUrl, groupedFindings, summary, narrative);
    }

    /**
     * Collapses every {@link Finding} sharing the same module/type/description/recommendation
     * into one {@link FindingGroup} with a list of occurrences, instead of one full object per
     * affected endpoint - a scan flagging the same missing-rate-limiting issue on twenty
     * endpoints produces one group with twenty occurrences, not twenty near-identical findings
     * repeating the same description and recommendation text. A {@link LinkedHashMap} preserves
     * first-seen order, and {@code ScanService} runs one module across every endpoint before the
     * next starts, so groups already come out ordered by module, in the order modules ran.
     */
    private List<FindingGroup> groupFindings(List<Finding> findings) {
        Map<GroupKey, List<FindingOccurrence>> byKey = new LinkedHashMap<>();
        for (Finding finding : findings) {
            GroupKey key = new GroupKey(finding.module(), finding.type(), finding.description(), finding.recommendation());
            byKey.computeIfAbsent(key, k -> new ArrayList<>()).add(new FindingOccurrence(
                    finding.id(), finding.severity(), finding.endpointUrl(), finding.method(),
                    finding.parameter(), finding.payload(), finding.evidence()));
        }
        return byKey.entrySet().stream()
                .map(entry -> new FindingGroup(entry.getKey().module(), entry.getKey().type(),
                        entry.getKey().description(), entry.getKey().recommendation(), entry.getValue()))
                .toList();
    }

    private record GroupKey(String module, VulnerabilityType type, String description, String recommendation) {
    }

    private ScanSummary summarize(List<Finding> findings, boolean possiblyRateLimited) {
        Map<Severity, Integer> countsBySeverity = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            countsBySeverity.put(severity, 0);
        }
        Map<VulnerabilityType, Integer> countsByType = new EnumMap<>(VulnerabilityType.class);
        for (VulnerabilityType type : VulnerabilityType.values()) {
            countsByType.put(type, 0);
        }

        int riskScore = 0;
        for (Finding finding : findings) {
            countsBySeverity.merge(finding.severity(), 1, Integer::sum);
            countsByType.merge(finding.type(), 1, Integer::sum);
            riskScore += SEVERITY_WEIGHTS.get(finding.severity());
        }

        Severity overallRisk = findings.stream()
                .map(Finding::severity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.INFO);
        return new ScanSummary(findings.size(), countsBySeverity, countsByType, overallRisk, riskScore, possiblyRateLimited);
    }

    private String buildNarrative(String targetUrl, long durationMillis, int endpointsDiscovered,
                                   int endpointsTested, String openApiSpecUrl, ScanSummary summary,
                                   RequestStats requestStats) {
        StringBuilder narrative = new StringBuilder();
        narrative.append("Investigation of ").append(targetUrl)
                .append(" completed in ").append(formatDuration(durationMillis)).append(". ");

        if (openApiSpecUrl != null) {
            narrative.append("Endpoints discovered via OpenAPI/Swagger spec (").append(openApiSpecUrl)
                    .append("): ").append(endpointsDiscovered).append(". ");
        } else {
            narrative.append("Endpoints discovered via HTML page scan of the target: ")
                    .append(endpointsDiscovered).append(". ");
        }

        if (endpointsTested < endpointsDiscovered) {
            narrative.append("Actually tested ").append(endpointsTested)
                    .append(" (configured HTTP method filter and/or max-endpoint limit). ");
        }

        if (summary.totalFindings() == 0) {
            narrative.append("No vulnerabilities detected.");
        } else {
            String severityBreakdown = summary.countsBySeverity().entrySet().stream()
                    .filter(entry -> entry.getValue() > 0)
                    .sorted(Comparator.comparingInt((Map.Entry<Severity, Integer> entry) -> entry.getKey().ordinal()).reversed())
                    .map(entry -> entry.getValue() + " " + entry.getKey())
                    .collect(Collectors.joining(", "));
            narrative.append("Detected ").append(summary.totalFindings())
                    .append(" vulnerabilities (overall risk: ").append(summary.overallRisk())
                    .append(", risk score: ").append(summary.riskScore())
                    .append("): ").append(severityBreakdown).append(". ");

            String typeBreakdown = summary.countsByType().entrySet().stream()
                    .filter(entry -> entry.getValue() > 0)
                    .sorted(Comparator.comparingInt((Map.Entry<VulnerabilityType, Integer> entry) -> entry.getValue()).reversed())
                    .map(entry -> entry.getValue() + " " + entry.getKey())
                    .collect(Collectors.joining(", "));
            narrative.append("By type: ").append(typeBreakdown).append(".");
        }

        if (summary.possiblyRateLimited()) {
            narrative.append(" WARNING: ")
                    .append(Math.round(requestStats.throttledRatio() * 100))
                    .append("% of requests (").append(requestStats.throttled()).append(" out of ")
                    .append(requestStats.total())
                    .append(") received a throttling response (429/423) during the scan itself - "
                            + "the target started limiting Sentinel before every endpoint could be "
                            + "tested reliably. The result above is partial: the absence of "
                            + "vulnerabilities is not guaranteed for endpoints tested after throttling began.");
        }
        return narrative.toString();
    }

    private String formatDuration(long durationMillis) {
        if (durationMillis < 1000) {
            return durationMillis + " ms";
        }
        return String.format(Locale.US, "%.1f seconds", durationMillis / 1000.0);
    }
}
