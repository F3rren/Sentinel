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
import tools.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Looks for a machine-readable API description (OpenAPI/Swagger) on the target and, when one
 * is found, enumerates every declared path/method as a candidate {@link Endpoint} - a much
 * more complete and reliable source than crawling HTML, for any project with Swagger wired up
 * (springdoc, springfox, or a hand-served swagger.json/openapi.json).
 * <p>
 * API gateways typically don't serve a single spec of their own: they aggregate one spec per
 * downstream service and expose the list via springdoc's {@code /v3/api-docs/swagger-config}
 * or springfox's {@code /swagger-resources}. When no single spec is found, this service also
 * follows that aggregation so the whole surface behind the gateway gets discovered.
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

    private static final List<String> AGGREGATOR_PATHS = List.of(
            "/v3/api-docs/swagger-config",
            "/swagger-resources"
    );

    private static final Set<String> SUPPORTED_METHODS = Set.of("get", "post", "put", "delete", "patch");

    private final SentinelHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OpenApiDiscoveryService(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public Optional<OpenApiDiscoveryResult> discover(String targetUrl) {
        String origin = originOf(targetUrl);
        if (origin == null) {
            return Optional.empty();
        }
        Optional<OpenApiDiscoveryResult> singleSpec = discoverSingleSpec(origin);
        if (singleSpec.isPresent()) {
            return singleSpec;
        }
        return discoverAggregatedSpecs(origin);
    }

    private Optional<OpenApiDiscoveryResult> discoverSingleSpec(String origin) {
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
                    return Optional.of(new OpenApiDiscoveryResult(specUrl, endpoints));
                }
            } catch (Exception e) {
                log.debug("OpenAPI probe failed for {}: {}", specUrl, e.getMessage());
            }
        }
        return Optional.empty();
    }

    /**
     * Behind a gateway there's usually no single spec, only an index of per-service ones.
     * Fetches that index, then every sub-spec it points to, resolving each sub-spec's paths
     * against the gateway's own origin - correct as long as the gateway forwards matched
     * routes without rewriting the path, which is the common case for prefix-based routing.
     */
    private Optional<OpenApiDiscoveryResult> discoverAggregatedSpecs(String origin) {
        for (String aggregatorPath : AGGREGATOR_PATHS) {
            String aggregatorUrl = origin + aggregatorPath;
            try {
                HttpResponseData response = httpClient.get(aggregatorUrl);
                if (response.statusCode() != 200 || response.bodyOrEmpty().isBlank()) {
                    continue;
                }
                JsonNode root = objectMapper.readTree(response.bodyOrEmpty());
                List<String> subSpecUrls = extractSubSpecUrls(root);
                if (subSpecUrls.isEmpty()) {
                    continue;
                }

                List<Endpoint> endpoints = new ArrayList<>();
                for (String subSpecUrl : subSpecUrls) {
                    fetchAndParseSubSpec(origin, subSpecUrl, endpoints);
                }
                if (!endpoints.isEmpty()) {
                    log.info("Discovered {} endpoint(s) across {} aggregated OpenAPI spec(s) via {}",
                            endpoints.size(), subSpecUrls.size(), aggregatorUrl);
                    return Optional.of(new OpenApiDiscoveryResult(aggregatorUrl, endpoints));
                }
            } catch (Exception e) {
                log.debug("OpenAPI aggregator probe failed for {}: {}", aggregatorUrl, e.getMessage());
            }
        }
        return Optional.empty();
    }

    private void fetchAndParseSubSpec(String origin, String subSpecUrl, List<Endpoint> endpoints) {
        String absoluteUrl = subSpecUrl.startsWith("http")
                ? subSpecUrl
                : origin + (subSpecUrl.startsWith("/") ? subSpecUrl : "/" + subSpecUrl);
        try {
            HttpResponseData response = httpClient.get(absoluteUrl);
            if (response.statusCode() != 200 || response.bodyOrEmpty().isBlank()) {
                return;
            }
            JsonNode subRoot = objectMapper.readTree(response.bodyOrEmpty());
            if (!looksLikeOpenApiSpec(subRoot)) {
                return;
            }
            for (Endpoint endpoint : parseSpec(origin, subRoot)) {
                boolean alreadyKnown = endpoints.stream()
                        .anyMatch(e -> e.method() == endpoint.method() && e.url().equals(endpoint.url()));
                if (!alreadyKnown) {
                    endpoints.add(endpoint);
                }
            }
        } catch (Exception e) {
            log.debug("Failed to fetch aggregated sub-spec {}: {}", absoluteUrl, e.getMessage());
        }
    }

    /**
     * Springdoc's {@code swagger-config} exposes {@code {"urls":[{"url":"...","name":"..."}]}};
     * springfox's {@code swagger-resources} is the same {@code [{"url":"...","name":"..."}]}
     * array at the document root instead of nested under a field. Both shapes are handled here.
     */
    private List<String> extractSubSpecUrls(JsonNode root) {
        Set<String> urls = new LinkedHashSet<>();
        JsonNode urlsNode = root.path("urls");
        JsonNode arrayNode = urlsNode.isArray() ? urlsNode : (root.isArray() ? root : null);
        if (arrayNode != null) {
            for (JsonNode entry : arrayNode) {
                String url = entry.path("url").asText("");
                if (!url.isBlank()) {
                    urls.add(url);
                }
            }
        }
        return new ArrayList<>(urls);
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

                String requestBodySample = buildRequestBodySample(root, operation);

                endpoints.add(new Endpoint(origin + resolvedPath, HttpMethod.valueOf(methodName.toUpperCase()),
                        queryParams, requestBodySample));
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
        return sampleValueForSchema(paramNode.path("schema"));
    }

    private String sampleValueForSchema(JsonNode schema) {
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
                case "date" -> LocalDate.now().toString();
                case "date-time" -> Instant.now().toString();
                case "email" -> "test@example.com";
                default -> "test";
            };
            default -> "test";
        };
    }

    /**
     * Builds a type-aware sample JSON body for operations that document one, so a POST/PUT/PATCH
     * expecting {@code application/json} gets something it can actually parse instead of an
     * empty form-encoded request it will just reject (415/400) before any attack module learns
     * anything. Values aren't random noise: reusing {@link #sampleValueForSchema} means numeric
     * and boolean fields get a value of the right JSON type, which is far more likely to pass
     * basic deserialization/validation and reach the endpoint's real logic.
     * <p>
     * Required properties are always populated. Optional properties are populated too unless
     * {@link #isUnsafeToGuess} flags them (a {@code pattern}-guarded string, an array, a nested
     * object) - for everything else (plain numbers, booleans, enums, formatted strings) sending a
     * real value is worth it: a Java primitive field (e.g. an {@code int} with {@code @Positive})
     * is often "optional" from the schema's point of view - {@code required} only reflects
     * {@code @NotNull}/{@code @NotBlank} - but still gets deserialized from a missing JSON field
     * to its primitive default ({@code 0}, {@code false}), which can fail validation on its own;
     * a real generated value avoids that trap. Falls back to populating every property when
     * {@code required} is absent entirely, since a fuller guess beats an empty body.
     */
    private String buildRequestBodySample(JsonNode root, JsonNode operation) {
        JsonNode schema = operation.path("requestBody").path("content").path("application/json").path("schema");
        if (!schema.isObject()) {
            return null;
        }
        JsonNode resolved = resolveSchemaRef(root, schema);
        JsonNode properties = resolved.path("properties");
        if (!properties.isObject()) {
            return null;
        }
        Set<String> requiredNames = requiredPropertyNames(resolved);

        ObjectNode body = objectMapper.createObjectNode();
        for (Map.Entry<String, JsonNode> property : properties.properties()) {
            boolean required = requiredNames.isEmpty() || requiredNames.contains(property.getKey());
            if (!required && isUnsafeToGuess(root, property.getValue())) {
                continue;
            }
            setSampleValue(root, body, property.getKey(), property.getValue());
        }
        return body.isEmpty() ? null : body.toString();
    }

    /**
     * An optional property is worth populating only when a generic sample can't make its
     * validation worse than leaving it out. A {@code pattern} is the clearest case (a regex we
     * can't satisfy in general). Collections and nested objects are the other: JSR-380's
     * {@code @Size}/{@code @NotEmpty} (and cascaded {@code @Valid} on a nested DTO) validate a
     * *present* value's shape, so the empty array/object {@link #setSampleValue} would otherwise
     * emit can fail validation that an absent (null) field would have skipped entirely - the same
     * trap this method exists to avoid, just via a container instead of a bad scalar.
     */
    private boolean isUnsafeToGuess(JsonNode root, JsonNode propertySchema) {
        JsonNode resolved = resolveSchemaRef(root, propertySchema);
        if (resolved.has("pattern")) {
            return true;
        }
        String type = resolved.path("type").asText("string");
        return "array".equals(type) || "object".equals(type);
    }

    private Set<String> requiredPropertyNames(JsonNode schema) {
        Set<String> names = new LinkedHashSet<>();
        for (JsonNode name : asList(schema.path("required"))) {
            if (name.isTextual()) {
                names.add(name.asText());
            }
        }
        return names;
    }

    /**
     * A property can itself be a {@code $ref} - the usual shape for an enum field, documented
     * as its own named schema (e.g. {@code AquariumType}) rather than inlined. Resolving it
     * here, not just once for the whole request body, is what lets {@link #sampleValueForSchema}
     * find the real {@code enum} list and pick an actual constant instead of falling back to a
     * generic string that fails enum deserialization before validation even runs.
     */
    private void setSampleValue(JsonNode root, ObjectNode target, String name, JsonNode propertySchema) {
        JsonNode resolved = resolveSchemaRef(root, propertySchema);
        String type = resolved.path("type").asText("string");
        switch (type) {
            case "integer" -> target.put(name, 1);
            case "number" -> target.put(name, 1.0);
            case "boolean" -> target.put(name, true);
            case "array" -> target.putArray(name);
            case "object" -> target.putObject(name);
            default -> target.put(name, sampleValueForSchema(resolved));
        }
    }

    /**
     * Follows a single {@code $ref: #/components/schemas/Name} indirection against the spec's
     * own {@code components.schemas} section - the common case for a DTO-shaped request body.
     * Schemas combined via allOf/oneOf/anyOf, or refs into another document, are out of scope:
     * this returns an empty object rather than guessing, which {@link #buildRequestBodySample}
     * treats as "nothing to send".
     */
    private JsonNode resolveSchemaRef(JsonNode root, JsonNode schema) {
        if (!schema.has("$ref")) {
            return schema;
        }
        String ref = schema.path("$ref").asText("");
        String prefix = "#/components/schemas/";
        if (!ref.startsWith(prefix)) {
            return objectMapper.createObjectNode();
        }
        JsonNode resolved = root.path("components").path("schemas").path(ref.substring(prefix.length()));
        return resolved.isObject() ? resolved : objectMapper.createObjectNode();
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
