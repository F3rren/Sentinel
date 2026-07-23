package com.f3rren.sentinel.model;

import org.springframework.http.HttpMethod;

import java.util.List;

/**
 * A candidate endpoint discovered during crawling (link with query string, or HTML form),
 * along with the parameters that will be fuzzed by attack modules.
 */
public record Endpoint(String url, HttpMethod method, List<EndpointParam> params) {
}
