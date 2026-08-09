package com.f3rren.sentinel.http;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public record HttpResponseData(int statusCode, String body, long elapsedMillis, Map<String, String> headers) {

    public HttpResponseData(int statusCode, String body, long elapsedMillis) {
        this(statusCode, body, elapsedMillis, Map.of());
    }

    public String bodyOrEmpty() {
        return body == null ? "" : body;
    }

    /** HTTP header names are case-insensitive (RFC 7230); lookup normalizes to lower case. */
    public Optional<String> header(String name) {
        return Optional.ofNullable(headers.get(name.toLowerCase(Locale.ROOT)));
    }
}
