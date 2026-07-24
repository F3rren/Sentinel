package com.f3rren.sentinel.model;

import org.springframework.http.HttpMethod;

import java.util.List;

/**
 * A candidate endpoint discovered during crawling (link with query string, or HTML form) or
 * from an OpenAPI spec, along with the parameters that will be fuzzed by attack modules and,
 * when the spec documents a JSON request body, a type-aware sample of it - without one, a
 * POST/PUT/PATCH endpoint expecting a body gets an empty form-encoded request instead and
 * typically just rejects it (415/400) before any attack module learns anything useful.
 */
public record Endpoint(String url, HttpMethod method, List<EndpointParam> params, String requestBodySample) {

    public Endpoint(String url, HttpMethod method, List<EndpointParam> params) {
        this(url, method, params, null);
    }
}
