package com.f3rren.sentinel.discovery.openapi;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Looks for a machine-readable API description (OpenAPI/Swagger) on the target and, when one
 * is found, enumerates every declared path/method as a candidate {@link Endpoint} - a much
 * more complete and reliable source than crawling HTML, for any project with Swagger wired up
 * (springdoc, springfox, or a hand-served swagger.json/openapi.json).
 */
@Service
public class OpenApiDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(OpenApiDiscoveryService.class);

    private static final List<String> CANDIDATE_SPEC_PATHS = List.of(
            "/v3/api-docs",
            "/v2/api-docs",
            "/api-docs",
            "/swagger.json",
            "/openapi.json",
            "/swagger/v1/swagger.json"
    );

    private static final Set<String> SUPPORTED_METHODS = Set.of("get", "post", "put", "delete", "patch");

    private final SentinelHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OpenApiDiscoveryService(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public java.util.Optional<OpenApiDiscoveryResult> discover(String targetUrl) {
        String origin = originOf(targetUrl);
        if (origin == null) {
            return java.util.Optional.empty();
        }
        for (String candidate : CANDIDATE_SPEC_PATHS) {
            String specUrl = origin + candidate;
            try {
                HttpResponseData response = httpClient.get(specUrl);
                if (response.statusCode() != 200 || response.bodyOrEmpty().isBlank()) {
                    continue;
                }
                JsonNode root = objectMapper.readTree(response.bodyOrEmpty());
                if (!looksLikeOpenApiSpec(root)) {
                    continue;
                }
                List<Endpoint> endpoints = parseSpec(origin, root);
                if (!endpoints.isEmpty()) {
                    log.info("Discovered {} endpoint(s) from OpenAPI/Swagger spec at {}", endpoints.size(), specUrl);
                    return java.util.Optional.of(new OpenApiDiscoveryResult(specUrl, endpoints));
                }
            } catch (Exception e) {
                log.debug("OpenAPI probe failed for {}: {}", specUrl, e.getMessage());
            }
        }
        return java.util.Optional.empty();
    }

    private boolean looksLikeOpenApiSpec(JsonNode root) {
        return root.isObject() && root.path("paths").isObject() && (root.has("openapi") || root.has("swagger"));
    }

    private List<Endpoint> parseSpec(String origin, JsonNode root) {
        List<Endpoint> endpoints = new ArrayList<>();
        JsonNode paths = root.path("paths");
        for (Map.Entry<String, JsonNode> pathEntry : paths.properties()) {
            String pathTemplate = pathEntry.getKey();
            JsonNode pathItem = pathEntry.getValue();
            if (!pathItem.isObject()) {
                continue;
            }
            List<JsonNode> sharedParams = asList(pathItem.path("parameters"));

            for (Map.Entry<String, JsonNode> opEntry : pathItem.properties()) {
                String methodName = opEntry.getKey().toLowerCase();
                if (!SUPPORTED_METHODS.contains(methodName) || !opEntry.getValue().isObject()) {
                    continue;
                }
                JsonNode operation = opEntry.getValue();

                List<JsonNode> params = new ArrayList<>(sharedParams);
                params.addAll(asList(operation.path("parameters")));

                String resolvedPath = resolvePathParams(pathTemplate, params);
                if (resolvedPath == null) {
                    // A path parameter isn't documented, so we can't build a valid concrete URL.
                    continue;
                }

                List<EndpointParam> queryParams = params.stream()
                        .filter(p -> "query".equals(p.path("in").asText()))
                        .map(p -> p.path("name").asText())
                        .filter(name -> !name.isBlank())
                        .distinct()
                        .map(name -> new EndpointParam(name, sampleValueForParameter(findParam(params, name))))
                        .toList();

                endpoints.add(new Endpoint(origin + resolvedPath, HttpMethod.valueOf(methodName.toUpperCase()), queryParams));
            }
        }
        return endpoints;
    }

    private JsonNode findParam(List<JsonNode> params, String name) {
        return params.stream()
                .filter(p -> name.equals(p.path("name").asText()) && "query".equals(p.path("in").asText()))
                .findFirst()
                .orElseGet(() -> objectMapper.createObjectNode());
    }

    private String resolvePathParams(String pathTemplate, List<JsonNode> params) {
        String resolved = pathTemplate;
        for (JsonNode param : params) {
            if (!"path".equals(param.path("in").asText())) {
                continue;
            }
            String name = param.path("name").asText();
            if (name.isBlank()) {
                continue;
            }
            String value = URLEncoder.encode(sampleValueForParameter(param), StandardCharsets.UTF_8);
            resolved = resolved.replace("{" + name + "}", value);
        }
        return resolved.contains("{") ? null : resolved;
    }

    private String sampleValueForParameter(JsonNode paramNode) {
        if (paramNode.has("example") && !paramNode.path("example").asText("").isBlank()) {
            return paramNode.path("example").asText();
        }
        JsonNode schema = paramNode.path("schema");
        if (schema.has("example") && !schema.path("example").asText("").isBlank()) {
            return schema.path("example").asText();
        }
        if (schema.path("enum").isArray() && !schema.path("enum").isEmpty()) {
            return schema.path("enum").get(0).asText();
        }
        String type = schema.path("type").asText("string");
        String format = schema.path("format").asText("");
        return switch (type) {
            case "integer", "number" -> "1";
            case "boolean" -> "true";
            case "string" -> switch (format) {
                case "uuid" -> "00000000-0000-0000-0000-000000000001";
                case "date" -> "2024-01-01";
                case "date-time" -> "2024-01-01T00:00:00Z";
                case "email" -> "test@example.com";
                default -> "test";
            };
            default -> "test";
        };
    }

    private List<JsonNode> asList(JsonNode arrayNode) {
        List<JsonNode> list = new ArrayList<>();
        if (arrayNode.isArray()) {
            arrayNode.forEach(list::add);
        }
        return list;
    }

    private String originOf(String targetUrl) {
        try {
            URI uri = URI.create(targetUrl);
            if (uri.getScheme() == null || uri.getAuthority() == null) {
                return null;
            }
            return uri.getScheme() + "://" + uri.getAuthority();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
