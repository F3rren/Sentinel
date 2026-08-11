package com.f3rren.sentinel.model;

/**
 * One concrete instance of a {@link FindingGroup} - the fields that differ per endpoint, split
 * out from the fields that don't (module/type/description/recommendation, identical across
 * every occurrence of the same vulnerability) so a report with many affected endpoints doesn't
 * repeat that shared text once per endpoint.
 */
public record FindingOccurrence(
        String id,
        Severity severity,
        String endpointUrl,
        String method,
        String parameter,
        String payload,
        String evidence
) {
}
