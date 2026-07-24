package com.f3rren.sentinel.model;

import java.util.Map;

public record ScanSummary(
        int totalFindings,
        Map<Severity, Integer> countsBySeverity,
        Map<VulnerabilityType, Integer> countsByType,
        Severity overallRisk,
        int riskScore
) {
}
