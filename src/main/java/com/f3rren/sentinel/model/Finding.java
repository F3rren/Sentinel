package com.f3rren.sentinel.model;

public record Finding(
        String id,
        VulnerabilityType type,
        Severity severity,
        String endpointUrl,
        String method,
        String parameter,
        String payload,
        String description,
        String evidence,
        String recommendation
) {
}
