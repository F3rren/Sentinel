package com.f3rren.sentinel.discovery;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Crawls a single page of the target and extracts candidate injectable endpoints:
 * links with a query string, and HTML forms. This is intentionally shallow (single page,
 * no recursive crawl) to keep the first version fast and predictable.
 */
@Service
public class EndpointDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(EndpointDiscoveryService.class);

    private static final Set<String> SKIPPED_INPUT_TYPES = Set.of("submit", "button", "image", "file", "reset");

    private final SentinelHttpClient httpClient;

    public EndpointDiscoveryService(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public List<Endpoint> discover(String baseUrl) {
        List<Endpoint> endpoints = new ArrayList<>();
        try {
            HttpResponseData response = httpClient.get(baseUrl);
            if (response.body() == null || response.body().isBlank()) {
                return endpoints;
            }
            Document document = Jsoup.parse(response.body(), baseUrl);
            endpoints.addAll(extractLinkEndpoints(document, baseUrl));
            endpoints.addAll(extractFormEndpoints(document, baseUrl));
        } catch (Exception e) {
            log.warn("Endpoint discovery failed for {}: {}", baseUrl, e.getMessage());
        }
        return endpoints;
    }

    private List<Endpoint> extractLinkEndpoints(Document document, String baseUrl) {
        List<Endpoint> result = new ArrayList<>();
        for (Element link : document.select("a[href]")) {
            String href = link.absUrl("href");
            if (href.isBlank() || !sameHost(href, baseUrl)) {
                continue;
            }
            URI uri;
            try {
                uri = URI.create(href);
            } catch (IllegalArgumentException e) {
                continue;
            }
            if (uri.getRawQuery() == null || uri.getRawQuery().isBlank()) {
                continue;
            }
            List<EndpointParam> params = parseQueryParams(uri.getRawQuery());
            if (!params.isEmpty()) {
                result.add(new Endpoint(stripQuery(href), HttpMethod.GET, params));
            }
        }
        return result;
    }

    private List<Endpoint> extractFormEndpoints(Document document, String baseUrl) {
        List<Endpoint> result = new ArrayList<>();
        for (Element form : document.select("form")) {
            String action = form.hasAttr("action") ? form.absUrl("action") : baseUrl;
            if (action.isBlank()) {
                action = baseUrl;
            }
            HttpMethod method = "post".equalsIgnoreCase(form.attr("method")) ? HttpMethod.POST : HttpMethod.GET;

            List<EndpointParam> params = new ArrayList<>();
            for (Element field : form.select("input, textarea, select")) {
                String name = field.attr("name");
                if (name.isBlank()) {
                    continue;
                }
                String type = field.attr("type").toLowerCase();
                if (SKIPPED_INPUT_TYPES.contains(type)) {
                    continue;
                }
                params.add(new EndpointParam(name, sampleValueFor(field, type)));
            }
            if (!params.isEmpty()) {
                result.add(new Endpoint(action, method, params));
            }
        }
        return result;
    }

    private String sampleValueFor(Element field, String type) {
        if (field.hasAttr("value") && !field.attr("value").isBlank()) {
            return field.attr("value");
        }
        return switch (type) {
            case "email" -> "test@example.com";
            case "number", "range" -> "1";
            case "checkbox", "radio" -> "on";
            default -> "test";
        };
    }

    private List<EndpointParam> parseQueryParams(String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "1";
            if (!key.isBlank()) {
                params.put(key, value.isBlank() ? "1" : value);
            }
        }
        return params.entrySet().stream()
                .map(e -> new EndpointParam(e.getKey(), e.getValue()))
                .toList();
    }

    private String stripQuery(String url) {
        int idx = url.indexOf('?');
        return idx == -1 ? url : url.substring(0, idx);
    }

    private boolean sameHost(String href, String baseUrl) {
        try {
            URI hrefUri = URI.create(href);
            URI baseUri = URI.create(baseUrl);
            return hrefUri.getHost() == null || hrefUri.getHost().equalsIgnoreCase(baseUri.getHost());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
