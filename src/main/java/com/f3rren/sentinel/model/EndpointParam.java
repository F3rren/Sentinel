package com.f3rren.sentinel.model;

/**
 * A single injectable parameter discovered on an endpoint, with a benign sample value
 * used to build the baseline request before fuzzing.
 */
public record EndpointParam(String name, String sampleValue) {
}
