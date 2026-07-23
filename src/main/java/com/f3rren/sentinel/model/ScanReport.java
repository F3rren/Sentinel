package com.f3rren.sentinel.model;

import java.time.Instant;
import java.util.List;

public record ScanReport(
        String id,
        String targetUrl,
        Instant startedAt,
        Instant finishedAt,
        long durationMillis,
        int endpointsDiscovered,
        String openApiSpecUrl,
        List<Finding> findings,
        ScanSummary summary
) {
}
