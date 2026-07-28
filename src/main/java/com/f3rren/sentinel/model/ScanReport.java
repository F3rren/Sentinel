package com.f3rren.sentinel.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ScanReport(
        String id,
        String targetUrl,
        Instant startedAt,
        Instant finishedAt,
        long durationMillis,
        int endpointsDiscovered,
        int endpointsTested,
        String openApiSpecUrl,
        List<Finding> findings,
        Map<String, List<Finding>> findingsByModule,
        ScanSummary summary,
        String narrative
) {
}
