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
import java.util.Map;

/**
 * Aggregates raw findings into a report with per-severity counts and an overall risk rating,
 * so a caller does not have to walk the findings list itself to know how bad things are.
 */
@Component
public class ReportGenerator {

    public ScanReport buildReport(String id, String targetUrl, Instant startedAt, Instant finishedAt,
                                   int endpointsDiscovered, List<Finding> findings) {
        ScanSummary summary = summarize(findings);
        long durationMillis = Duration.between(startedAt, finishedAt).toMillis();
        return new ScanReport(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered, findings, summary);
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
}
