package com.f3rren.sentinel.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies exchange() sends the real HTTP verb and puts parameters where that verb expects
 * them (query string for body-less verbs, form body for verbs that carry one) - this matters
 * once endpoints come from an OpenAPI spec, which can declare GET/POST/PUT/DELETE/PATCH.
 */
class SentinelHttpClientTest {

    private HttpServer server;
    private String baseUrl;
    private SentinelHttpClient httpClient;
    private volatile String lastMethod;
    private volatile String lastQuery;
    private volatile String lastBody;
    private volatile String lastContentType;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/echo", this::echoHandler);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        httpClient = new SentinelHttpClient("Sentinel-Test/1.0", 5000, 3000);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void getSendsParamsAsQueryString() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("q", "widget");

        HttpResponseData response = httpClient.exchange(HttpMethod.GET, baseUrl + "/echo", params);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(lastMethod).isEqualTo("GET");
        assertThat(lastQuery).isEqualTo("q=widget");
        assertThat(lastBody).isEmpty();
    }

    @Test
    void deleteSendsParamsAsQueryString() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("id", "42");

        httpClient.exchange(HttpMethod.DELETE, baseUrl + "/echo", params);

        assertThat(lastMethod).isEqualTo("DELETE");
        assertThat(lastQuery).isEqualTo("id=42");
        assertThat(lastBody).isEmpty();
    }

    @Test
    void postSendsParamsAsFormBody() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("username", "admin");

        httpClient.exchange(HttpMethod.POST, baseUrl + "/echo", params);

        assertThat(lastMethod).isEqualTo("POST");
        assertThat(lastQuery).isNullOrEmpty();
        assertThat(lastBody).isEqualTo("username=admin");
    }

    @Test
    void putSendsParamsAsFormBody() throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("name", "widget");

        httpClient.exchange(HttpMethod.PUT, baseUrl + "/echo", params);

        assertThat(lastMethod).isEqualTo("PUT");
        assertThat(lastBody).isEqualTo("name=widget");
    }

    @Test
    void sendsJsonBodyAndStillAppendsQueryParamsToUrlWhenBothArePresent() throws Exception {
        Map<String, String> queryParams = new LinkedHashMap<>();
        queryParams.put("dryRun", "true");

        httpClient.exchange(HttpMethod.POST, baseUrl + "/echo", queryParams, "{\"name\":\"widget\"}");

        assertThat(lastMethod).isEqualTo("POST");
        assertThat(lastQuery).isEqualTo("dryRun=true");
        assertThat(lastBody).isEqualTo("{\"name\":\"widget\"}");
        assertThat(lastContentType).isEqualTo("application/json");
    }

    @Test
    void fallsBackToFormEncodingWhenJsonBodyIsNull() throws Exception {
        Map<String, String> queryParams = new LinkedHashMap<>();
        queryParams.put("name", "widget");

        httpClient.exchange(HttpMethod.POST, baseUrl + "/echo", queryParams, null);

        assertThat(lastBody).isEqualTo("name=widget");
        assertThat(lastContentType).isEqualTo("application/x-www-form-urlencoded");
    }

    @Test
    void ignoresJsonBodyForBodylessVerbs() throws Exception {
        Map<String, String> queryParams = new LinkedHashMap<>();
        queryParams.put("id", "1");

        httpClient.exchange(HttpMethod.GET, baseUrl + "/echo", queryParams, "{\"ignored\":true}");

        assertThat(lastMethod).isEqualTo("GET");
        assertThat(lastQuery).isEqualTo("id=1");
        assertThat(lastBody).isEmpty();
    }

    private void echoHandler(HttpExchange exchange) throws IOException {
        lastMethod = exchange.getRequestMethod();
        lastQuery = exchange.getRequestURI().getRawQuery();
        lastContentType = exchange.getRequestHeaders().getFirst("Content-Type");
        try (InputStream is = exchange.getRequestBody()) {
            lastBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
        byte[] bytes = "ok".getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}
