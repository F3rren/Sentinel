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
        int endpointsTested,
        String openApiSpecUrl,
        List<FindingGroup> findings,
        ScanSummary summary,
        String narrative,
        // Optional natural-language summary produced by the opt-in AI analysis slice
        // (sentinel.ai.enabled). Null whenever AI analysis is disabled or unavailable - it is a
        // best-effort commentary layered on top of the deterministic findings, never a source of
        // them, so a report is complete and valid with this left null.
        String aiAnalysis
) {

    /**
     * Backward-compatible constructor for every producer that builds a report without AI
     * analysis (the report generator, tests, deserialization of older reports). Delegates to the
     * canonical constructor with {@code aiAnalysis} left null so the field can be attached later
     * via {@link #withAiAnalysis(String)} without every call site having to know about it.
     */
    public ScanReport(
            String id,
            String targetUrl,
            Instant startedAt,
            Instant finishedAt,
            long durationMillis,
            int endpointsDiscovered,
            int endpointsTested,
            String openApiSpecUrl,
            List<FindingGroup> findings,
            ScanSummary summary,
            String narrative
    ) {
        this(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered, endpointsTested,
                openApiSpecUrl, findings, summary, narrative, null);
    }

    /**
     * Returns a copy of this report with the AI analysis text attached. Used to layer the
     * optional AI commentary onto an already-finished, already-redacted report without mutating
     * it or threading the value through the whole report-building pipeline.
     */
    public ScanReport withAiAnalysis(String aiAnalysis) {
        return new ScanReport(id, targetUrl, startedAt, finishedAt, durationMillis, endpointsDiscovered,
                endpointsTested, openApiSpecUrl, findings, summary, narrative, aiAnalysis);
    }
}
