package com.f3rren.sentinel.http;

public record HttpResponseData(int statusCode, String body, long elapsedMillis) {

    public String bodyOrEmpty() {
        return body == null ? "" : body;
    }
}
