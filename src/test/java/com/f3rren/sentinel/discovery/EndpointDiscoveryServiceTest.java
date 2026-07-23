package com.f3rren.sentinel.discovery;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EndpointDiscoveryServiceTest {

    @Mock
    private SentinelHttpClient httpClient;

    @Test
    void extractsEndpointsFromLinksAndForms() throws Exception {
        String html = """
                <html><body>
                  <a href="/search?q=test&category=1">search</a>
                  <a href="/about">about (no query, skipped)</a>
                  <form action="/login" method="post">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <input type="hidden" name="csrf" value="abc123" />
                    <button type="submit">Login</button>
                  </form>
                </body></html>
                """;
        when(httpClient.get("http://localhost:8080")).thenReturn(new HttpResponseData(200, html, 5));

        EndpointDiscoveryService service = new EndpointDiscoveryService(httpClient);
        List<Endpoint> endpoints = service.discover("http://localhost:8080");

        assertThat(endpoints).hasSize(2);

        Endpoint search = endpoints.stream().filter(e -> e.url().endsWith("/search")).findFirst().orElseThrow();
        assertThat(search.method()).isEqualTo(HttpMethod.GET);
        assertThat(search.params()).extracting("name").containsExactlyInAnyOrder("q", "category");

        Endpoint login = endpoints.stream().filter(e -> e.url().endsWith("/login")).findFirst().orElseThrow();
        assertThat(login.method()).isEqualTo(HttpMethod.POST);
        assertThat(login.params()).extracting("name").containsExactlyInAnyOrder("username", "password", "csrf");
    }

    @Test
    void returnsEmptyListWhenTargetUnreachable() throws Exception {
        when(httpClient.get("http://localhost:9999")).thenThrow(new java.io.IOException("connection refused"));

        EndpointDiscoveryService service = new EndpointDiscoveryService(httpClient);
        List<Endpoint> endpoints = service.discover("http://localhost:9999");

        assertThat(endpoints).isEmpty();
    }
}
