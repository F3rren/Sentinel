package com.f3rren.sentinel.report;

import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
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
 * Aggregates raw findings into a report with per-severity counts and an overall risk rating,
 * plus a plain-language narrative summarizing the same numbers - useful when the report is
 * read directly (e.g. printed from curl) instead of consumed by another program.
 */
@Component
public class ReportGenerator {

    public ScanReport buildReport(String id, String targetUrl, Instant startedAt, Instant finishedAt,
                                   int endpointsDiscovered, String openApiSpecUrl, List<Finding> findings) {
        ScanSummary summary = summarize(findings);
        long durationMillis = Duration.between(startedAt, finishedAt).toMillis();
        String narrative = buildNarrative(targetUrl, durationMillis, endpointsDiscovered, openApiSpecUrl, summary);
        return new ScanReport(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered, openApiSpecUrl, findings, summary, narrative);
    }

    private ScanSummary summarize(List<Finding> findings) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, 0);
        }
        for (Finding finding : findings) {
            counts.merge(finding.severity(), 1, Integer::sum);
        }
        Severity overallRisk = findings.stream()
                .map(Finding::severity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.INFO);
        return new ScanSummary(findings.size(), counts, overallRisk);
    }

    private String buildNarrative(String targetUrl, long durationMillis, int endpointsDiscovered,
                                   String openApiSpecUrl, ScanSummary summary) {
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

        if (summary.totalFindings() == 0) {
            narrative.append("Nessuna vulnerabilità rilevata.");
        } else {
            String breakdown = summary.countsBySeverity().entrySet().stream()
                    .filter(entry -> entry.getValue() > 0)
                    .sorted(Comparator.comparingInt((Map.Entry<Severity, Integer> entry) -> entry.getKey().ordinal()).reversed())
                    .map(entry -> entry.getValue() + " " + entry.getKey())
                    .collect(Collectors.joining(", "));
            narrative.append("Rilevate ").append(summary.totalFindings())
                    .append(" vulnerabilità (rischio complessivo: ").append(summary.overallRisk())
                    .append("): ").append(breakdown).append(".");
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
