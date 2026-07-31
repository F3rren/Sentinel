package com.f3rren.sentinel.report;

import com.f3rren.sentinel.http.RequestStats;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
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
        Map<String, List<Finding>> findingsByModule = groupByModule(findings);
        long durationMillis = Duration.between(startedAt, finishedAt).toMillis();
        String narrative = buildNarrative(targetUrl, durationMillis, endpointsDiscovered, endpointsTested,
                openApiSpecUrl, summary, requestStats);
        return new ScanReport(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered, endpointsTested,
                openApiSpecUrl, findings, findingsByModule, summary, narrative);
    }

    /**
     * The flat {@code findings} list stays for simple full iteration; this is the same data
     * organized into one section per attack module, in the order modules actually ran (a
     * {@link LinkedHashMap} preserves first-seen order, and {@code ScanService} runs one module
     * across every endpoint before the next starts, so findings already arrive grouped) - readable
     * directly from the report JSON without the caller re-grouping by {@link Finding#module()}.
     */
    private Map<String, List<Finding>> groupByModule(List<Finding> findings) {
        return findings.stream()
                .collect(Collectors.groupingBy(Finding::module, LinkedHashMap::new, Collectors.toList()));
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
        narrative.append("Investigazione su ").append(targetUrl)
                .append(" completata in ").append(formatDuration(durationMillis)).append(". ");

        if (openApiSpecUrl != null) {
            narrative.append("Endpoint individuati tramite spec OpenAPI/Swagger (").append(openApiSpecUrl)
                    .append("): ").append(endpointsDiscovered).append(". ");
        } else {
            narrative.append("Endpoint individuati tramite scansione della pagina HTML del target: ")
                    .append(endpointsDiscovered).append(". ");
        }

        if (endpointsTested < endpointsDiscovered) {
            narrative.append("Testati effettivamente ").append(endpointsTested)
                    .append(" (filtro sui metodi HTTP e/o limite massimo endpoint configurati). ");
        }

        if (summary.totalFindings() == 0) {
            narrative.append("Nessuna vulnerabilità rilevata.");
        } else {
            String severityBreakdown = summary.countsBySeverity().entrySet().stream()
                    .filter(entry -> entry.getValue() > 0)
                    .sorted(Comparator.comparingInt((Map.Entry<Severity, Integer> entry) -> entry.getKey().ordinal()).reversed())
                    .map(entry -> entry.getValue() + " " + entry.getKey())
                    .collect(Collectors.joining(", "));
            narrative.append("Rilevate ").append(summary.totalFindings())
                    .append(" vulnerabilità (rischio complessivo: ").append(summary.overallRisk())
                    .append(", punteggio di rischio: ").append(summary.riskScore())
                    .append("): ").append(severityBreakdown).append(". ");

            String typeBreakdown = summary.countsByType().entrySet().stream()
                    .filter(entry -> entry.getValue() > 0)
                    .sorted(Comparator.comparingInt((Map.Entry<VulnerabilityType, Integer> entry) -> entry.getValue()).reversed())
                    .map(entry -> entry.getValue() + " " + entry.getKey())
                    .collect(Collectors.joining(", "));
            narrative.append("Per tipologia: ").append(typeBreakdown).append(".");
        }

        if (summary.possiblyRateLimited()) {
            narrative.append(" ATTENZIONE: il ")
                    .append(Math.round(requestStats.throttledRatio() * 100))
                    .append("% delle richieste (").append(requestStats.throttled()).append(" su ")
                    .append(requestStats.total())
                    .append(") ha ricevuto una risposta di throttling (429/423) durante la scansione stessa - "
                            + "il target ha iniziato a limitare Sentinel prima che tutti gli endpoint potessero "
                            + "essere testati in modo affidabile. Il risultato sopra e' parziale: l'assenza di "
                            + "vulnerabilita' non e' garantita per gli endpoint testati dopo l'inizio del throttling.");
        }
        return narrative.toString();
    }

    private String formatDuration(long durationMillis) {
        if (durationMillis < 1000) {
            return durationMillis + " ms";
        }
        return String.format(Locale.ITALIAN, "%.1f secondi", durationMillis / 1000.0);
    }
}
