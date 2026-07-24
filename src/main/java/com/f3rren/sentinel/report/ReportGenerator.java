package com.f3rren.sentinel.report;

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

    public ScanReport buildReport(String id, String targetUrl, Instant startedAt, Instant finishedAt,
                                   int endpointsDiscovered, int endpointsTested, String openApiSpecUrl,
                                   List<Finding> findings) {
        ScanSummary summary = summarize(findings);
        long durationMillis = Duration.between(startedAt, finishedAt).toMillis();
        String narrative = buildNarrative(targetUrl, durationMillis, endpointsDiscovered, endpointsTested, openApiSpecUrl, summary);
        return new ScanReport(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered, endpointsTested, openApiSpecUrl, findings, summary, narrative);
    }

    private ScanSummary summarize(List<Finding> findings) {
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
        return new ScanSummary(findings.size(), countsBySeverity, countsByType, overallRisk, riskScore);
    }

    private String buildNarrative(String targetUrl, long durationMillis, int endpointsDiscovered,
                                   int endpointsTested, String openApiSpecUrl, ScanSummary summary) {
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
        return narrative.toString();
    }

    private String formatDuration(long durationMillis) {
        if (durationMillis < 1000) {
            return durationMillis + " ms";
        }
        return String.format(Locale.ITALIAN, "%.1f secondi", durationMillis / 1000.0);
    }
}
