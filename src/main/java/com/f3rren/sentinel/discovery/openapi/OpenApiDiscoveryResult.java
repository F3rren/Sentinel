package com.f3rren.sentinel.discovery.openapi;

import com.f3rren.sentinel.model.Endpoint;

import java.util.List;

/**
 * Outcome of a successful OpenAPI/Swagger probe: where the spec was found and every
 * endpoint extracted from it.
 */
public record OpenApiDiscoveryResult(String specUrl, List<Endpoint> endpoints) {
}
