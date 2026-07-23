package com.f3rren.sentinel.http;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Thin wrapper around the JDK HTTP client used by every attack/discovery module.
 * Requests target a URL supplied at scan time, so a single stateless client is reused
 * instead of a per-target Spring RestClient.
 */
@Component
public class SentinelHttpClient {

    private final HttpClient httpClient;
    private final String userAgent;
    private final Duration requestTimeout;

    public SentinelHttpClient(
            @Value("${sentinel.scan.user-agent:Sentinel-Scanner/0.1 (+authorized-security-testing)}") String userAgent,
            @Value("${sentinel.scan.request-timeout-ms:8000}") long requestTimeoutMs,
            @Value("${sentinel.scan.connect-timeout-ms:5000}") long connectTimeoutMs
    ) {
        this.userAgent = userAgent;
        this.requestTimeout = Duration.ofMillis(requestTimeoutMs);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public HttpResponseData get(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(requestTimeout)
                .header("User-Agent", userAgent)
                .GET()
                .build();
        return send(request);
    }

    public HttpResponseData postForm(String url, Map<String, String> formParams) throws IOException, InterruptedException {
        String body = encodeForm(formParams);
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(requestTimeout)
                .header("User-Agent", userAgent)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        return send(request);
    }

    public HttpResponseData exchange(HttpMethod method, String url, Map<String, String> params) throws IOException, InterruptedException {
        if (method == HttpMethod.POST) {
            return postForm(url, params);
        }
        String separator = url.contains("?") ? "&" : "?";
        String query = encodeForm(params);
        String finalUrl = query.isEmpty() ? url : url + separator + query;
        return get(finalUrl);
    }

    private HttpResponseData send(HttpRequest request) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        long elapsed = System.currentTimeMillis() - start;
        return new HttpResponseData(response.statusCode(), response.body(), elapsed);
    }

    private String encodeForm(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> urlEncode(e.getKey()) + "=" + urlEncode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private String urlEncode(String value) {
        return java.net.URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
