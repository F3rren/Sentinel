package com.f3rren.sentinel.attack.idor;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.ScanIdentity;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Checks for IDOR/BOLA (Insecure Direct Object Reference / Broken Object Level Authorization):
 * whether one authenticated identity can read or modify a resource that a <em>different</em>
 * identity created. Unlike every other module, this needs two distinct identities to compare -
 * a concept none of the other modules have - so it's opt-in
 * ({@code sentinel.scan.idor.enabled=true}) and does nothing unless a scan request supplies both
 * (see {@code POST /api/scans}'s {@code identities} field).
 * <p>
 * v1 only implements the high-confidence case: identity A creates a resource, and the resulting
 * id (read from the response body) is used to probe identity B against that exact resource -
 * proof of ownership, not just "both got a 2xx on the same generic id". It only recognizes
 * top-level collection/item pairs (e.g. {@code POST /aquariums} + {@code GET /aquariums/{id}});
 * nested resources (e.g. {@code /aquariums/{id}/inhabitants/{inhabitantId}}) are out of scope,
 * since it's ambiguous which identity should be considered the "owner" of a nested id.
 * <p>
 * Holds state across the {@link #scan(Endpoint)} calls for a single scan (the created resource's
 * id, keyed by resource family) because this module is a singleton bean shared by every scan
 * Sentinel ever runs - {@link #beginScan(ScanContext)}/{@link #endScan()} bracket that state so
 * it never leaks from one scan into the next.
 */
@Component
// Runs before every other module (including sql-injection at Order(0)): this module makes very
// few requests overall (one create + one comparison per resource family), but that single create
// is a hard dependency - if it gets throttled by a rate limit another module already exhausted,
// the whole check silently no-ops for that family (a 429 there isn't distinguished from a real
// 403/404, on purpose - see recordCreatedResourceId). Going first gives it the cleanest possible
// shot at an unthrottled response before any other module's fuzzing burns the target's budget.
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(prefix = "sentinel.scan.idor", name = "enabled", havingValue = "true", matchIfMissing = false)
public class IdorScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(IdorScanner.class);

    private static final Set<HttpMethod> MUTATING_METHODS =
            Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE);

    private static final Pattern ID_SEGMENT =
            Pattern.compile("^([0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$");

    private static final int MAX_JSON_SEARCH_DEPTH = 4;

    private static final String RECOMMENDATION =
            "Verify server-side, on every request that references a resource by id, that the "
            + "authenticated identity actually owns (or is otherwise authorized on) that specific "
            + "resource - not just that it is generically logged in. Deny by default (403/404) "
            + "when the ownership check is missing or fails, rather than allowing by default.";

    private final SentinelHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, String> createdResourceIdByFamily = new HashMap<>();
    private final List<Endpoint> pendingItemEndpoints = new ArrayList<>();
    private ScanContext scanContext;

    public IdorScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "idor";
    }

    @Override
    public void beginScan(ScanContext context) {
        this.scanContext = context;
        this.createdResourceIdByFamily.clear();
        this.pendingItemEndpoints.clear();
    }

    /**
     * Every item-endpoint check is deferred to here rather than resolved eagerly during
     * {@link #scan(Endpoint)}: discovery order is not guaranteed to put a collection's create
     * before its item endpoints (e.g. an OpenAPI spec grouping every {@code /aquariums/{id}}
     * operation before {@code /aquariums} itself is common), so checking eagerly would
     * permanently miss any item endpoint discovered before its create. Resolving them all here
     * instead guarantees every create this scan will ever perform has already happened,
     * regardless of the order endpoints were discovered in.
     */
    @Override
    public List<Finding> endScan() {
        List<Finding> findings = new ArrayList<>();
        for (Endpoint endpoint : pendingItemEndpoints) {
            String family = familyKey(endpoint.url());
            String createdId = createdResourceIdByFamily.get(family);
            if (createdId == null) {
                // No proven ownership to test against was ever created in this same scan - v1
                // only implements the high-confidence, provable-ownership case, so skip silently
                // rather than guessing off the generic sample id discovery put in the URL.
                continue;
            }
            String urlWithCreatedId = replaceTrailingIdSegment(endpoint.url(), createdId);
            findings.addAll(checkCrossIdentityAccess(endpoint, urlWithCreatedId, createdId));
        }
        this.scanContext = null;
        this.createdResourceIdByFamily.clear();
        this.pendingItemEndpoints.clear();
        return findings;
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        if (scanContext == null || !scanContext.hasBothIdentities()) {
            return List.of();
        }

        if (isTopLevelCollectionCreate(endpoint)) {
            recordCreatedResourceId(endpoint);
            return List.of();
        }

        if (extractTrailingIdSegment(endpoint.url()).isPresent()) {
            pendingItemEndpoints.add(endpoint);
        }
        return List.of();
    }

    private void recordCreatedResourceId(Endpoint endpoint) {
        HttpResponseData response;
        try {
            response = httpClient.exchange(endpoint.method(), endpoint.url(), paramsOf(endpoint),
                    endpoint.requestBodySample(), headerMap(scanContext.identityA()));
        } catch (Exception e) {
            log.warn("IDOR setup (create as identity A) failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return;
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            log.warn("IDOR setup (create as identity A) got {} for {} {}: {}", response.statusCode(),
                    endpoint.method(), endpoint.url(),
                    response.header("x-auth-failure-reason").orElse(response.bodyOrEmpty()));
            return;
        }
        extractIdFromJson(response.bodyOrEmpty())
                .ifPresent(id -> createdResourceIdByFamily.put(familyKey(endpoint.url()), id));
    }

    private List<Finding> checkCrossIdentityAccess(Endpoint endpoint, String urlWithCreatedId, String createdId) {
        HttpResponseData responseAsB;
        try {
            responseAsB = httpClient.exchange(endpoint.method(), urlWithCreatedId, paramsOf(endpoint),
                    endpoint.requestBodySample(), headerMap(scanContext.identityB()));
        } catch (Exception e) {
            log.warn("IDOR cross-identity check failed for {} {}: {}", endpoint.method(), urlWithCreatedId, e.getMessage());
            return List.of();
        }

        if (responseAsB.statusCode() < 200 || responseAsB.statusCode() >= 300) {
            // Identity B was correctly denied - this is the secure, expected outcome, not a finding.
            return List.of();
        }

        Severity severity = MUTATING_METHODS.contains(endpoint.method()) ? Severity.CRITICAL : Severity.HIGH;
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.IDOR,
                severity,
                urlWithCreatedId,
                endpoint.method().name(),
                "",
                "",
                "A resource created by one identity was accessed or modified by a different identity without authorization.",
                "Identity A created the resource (id " + createdId + "); identity B then received status "
                        + responseAsB.statusCode() + " on " + endpoint.method() + " " + urlWithCreatedId
                        + " instead of a 401/403/404 denial.",
                RECOMMENDATION
        );
        return List.of(finding);
    }

    private Map<String, String> headerMap(ScanIdentity identity) {
        return Map.of(identity.header(), identity.value());
    }

    private Map<String, String> paramsOf(Endpoint endpoint) {
        Map<String, String> params = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            params.put(param.name(), param.sampleValue());
        }
        return params;
    }

    /**
     * A top-level collection create is a POST to a URL with exactly one path segment (e.g.
     * {@code /aquariums}) - excludes nested collections (e.g. {@code /aquariums/1/tasks}, which
     * has an ambiguous owner) by construction.
     */
    private boolean isTopLevelCollectionCreate(Endpoint endpoint) {
        return endpoint.method() == HttpMethod.POST && pathSegments(endpoint.url()).size() == 1;
    }

    /**
     * A top-level item URL has exactly two path segments (collection name + id), the second of
     * which looks like a numeric or UUID identifier - excludes nested item URLs by construction.
     */
    private Optional<String> extractTrailingIdSegment(String url) {
        List<String> segments = pathSegments(url);
        if (segments.size() != 2) {
            return Optional.empty();
        }
        String last = segments.get(1);
        return ID_SEGMENT.matcher(last).matches() ? Optional.of(last) : Optional.empty();
    }

    private String familyKey(String url) {
        List<String> segments = pathSegments(url);
        URI uri = URI.create(url);
        return uri.getScheme() + "://" + uri.getAuthority() + "/" + segments.get(0);
    }

    private String replaceTrailingIdSegment(String url, String newId) {
        int lastSlash = url.lastIndexOf('/');
        return url.substring(0, lastSlash + 1) + newId;
    }

    private List<String> pathSegments(String url) {
        String path;
        try {
            path = URI.create(url).getPath();
        } catch (IllegalArgumentException e) {
            return List.of();
        }
        return Arrays.stream(path.split("/")).filter(segment -> !segment.isBlank()).toList();
    }

    /**
     * Generic search for a field literally named "id" (case-insensitive) in a JSON response
     * body, checking each object's own fields before recursing into nested ones - this covers
     * both a flat {@code {"id": 5}} and an enveloped {@code {"success": true, "data": {"id": 5}}}
     * shape without assuming any particular API's response envelope.
     */
    private Optional<String> extractIdFromJson(String body) {
        if (body == null || body.isBlank()) {
            return Optional.empty();
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(body);
        } catch (Exception e) {
            return Optional.empty();
        }
        return findIdField(root, 0);
    }

    private Optional<String> findIdField(JsonNode node, int depth) {
        if (node == null || !node.isObject() || depth > MAX_JSON_SEARCH_DEPTH) {
            return Optional.empty();
        }
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            if ("id".equalsIgnoreCase(entry.getKey()) && entry.getValue().isValueNode()) {
                return Optional.of(entry.getValue().asText());
            }
        }
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            Optional<String> nested = findIdField(entry.getValue(), depth + 1);
            if (nested.isPresent()) {
                return nested;
            }
        }
        return Optional.empty();
    }
}
