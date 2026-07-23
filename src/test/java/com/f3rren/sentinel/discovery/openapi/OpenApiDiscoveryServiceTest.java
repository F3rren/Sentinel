package com.f3rren.sentinel.discovery.openapi;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OpenApiDiscoveryServiceTest {

    private static final String SPEC = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/api/search": {
                  "get": {
                    "parameters": [
                      {"name": "q", "in": "query", "schema": {"type": "string"}},
                      {"name": "page", "in": "query", "schema": {"type": "integer"}}
                    ]
                  }
                },
                "/api/users/{id}": {
                  "get": {
                    "parameters": [
                      {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
                    ]
                  },
                  "delete": {
                    "parameters": [
                      {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
                    ]
                  }
                },
                "/api/orders": {
                  "post": {
                    "parameters": [
                      {"name": "customerId", "in": "query", "schema": {"type": "string"}}
                    ]
                  }
                },
                "/api/broken/{missing}": {
                  "get": {}
                }
              }
            }
            """;

    @Mock
    private SentinelHttpClient httpClient;

    @Test
    void extractsEndpointsFromOpenApiSpec() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            if (url.endsWith("/v3/api-docs")) {
                return new HttpResponseData(200, SPEC, 5);
            }
            return new HttpResponseData(404, "", 5);
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        assertThat(result.get().specUrl()).isEqualTo("http://localhost:8080/v3/api-docs");

        List<Endpoint> endpoints = result.get().endpoints();
        assertThat(endpoints).hasSize(4);

        Endpoint search = find(endpoints, HttpMethod.GET, "http://localhost:8080/api/search");
        assertThat(search.params()).extracting("name").containsExactlyInAnyOrder("q", "page");

        Endpoint getUser = find(endpoints, HttpMethod.GET, "http://localhost:8080/api/users/1");
        assertThat(getUser.params()).isEmpty();

        Endpoint deleteUser = find(endpoints, HttpMethod.DELETE, "http://localhost:8080/api/users/1");
        assertThat(deleteUser.params()).isEmpty();

        Endpoint orders = find(endpoints, HttpMethod.POST, "http://localhost:8080/api/orders");
        assertThat(orders.params()).extracting("name").containsExactly("customerId");

        assertThat(endpoints).noneMatch(e -> e.url().contains("{"));
    }

    @Test
    void returnsEmptyWhenNoSpecIsFound() throws Exception {
        when(httpClient.get(anyString())).thenReturn(new HttpResponseData(404, "", 5));

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);

        assertThat(service.discover("http://localhost:8080")).isEmpty();
    }

    private Endpoint find(List<Endpoint> endpoints, HttpMethod method, String url) {
        return endpoints.stream()
                .filter(e -> e.method() == method && e.url().equals(url))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No endpoint found for " + method + " " + url));
    }
}
