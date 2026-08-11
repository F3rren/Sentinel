package com.f3rren.sentinel.attack.massassignment;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.discovery.SampleValues;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
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
import tools.jackson.databind.node.ObjectNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Checks for Mass Assignment / BOPLA (Broken Object Property Level Authorization): whether a
 * POST/PUT/PATCH endpoint blindly binds every property in the request body onto the resource it
 * creates or updates, including ones its documented request schema never advertised as
 * client-settable.
 * <p>
 * Like BFLA, this needs at least one real identity to reach a write endpoint at all (see {@code
 * POST /api/scans}'s {@code identities} field) - not to compare ownership the way IDOR does, just
 * as "a real authenticated caller" - so it's opt-in ({@code sentinel.scan.mass-assignment.enabled
 * =true}). Identity A is used when available, identity B otherwise; unlike IDOR this never needs
 * both, and unlike BFLA it never retries with the other identity on denial - a write endpoint
 * being probed here has side effects, so a single attempt keeps those to a minimum.
 * <p>
 * Detection is a heuristic on a small, fixed set of privilege/ownership-sounding field names
 * ({@code role}, {@code isAdmin}, {@code ownerId}, {@code verified}) - not real insight into the
 * target's actual model - added to the endpoint's own generated sample body wherever a candidate
 * isn't already one of its documented properties, then checked for whether the response echoes
 * that exact injected value back. Kept deliberately small and conservative, the same philosophy
 * BFLA's path-keyword list follows, to limit false positives rather than guessing broadly.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
@ConditionalOnProperty(prefix = "sentinel.scan.mass-assignment", name = "enabled", havingValue = "true", matchIfMissing = false)
public class MassAssignmentScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(MassAssignmentScanner.class);

    private static final Set<HttpMethod> BODY_METHODS = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH);

    private static final int MAX_JSON_SEARCH_DEPTH = 4;

    private static final Map<String, Severity> CANDIDATE_FIELDS;

    static {
        Map<String, Severity> fields = new LinkedHashMap<>();
        // Grant privilege outright if the server actually binds them - CRITICAL.
        fields.put("role", Severity.CRITICAL);
        fields.put("isAdmin", Severity.CRITICAL);
        // Compromise data integrity/ownership rather than granting privilege directly - HIGH.
        fields.put("ownerId", Severity.HIGH);
        fields.put("verified", Severity.HIGH);
        CANDIDATE_FIELDS = Collections.unmodifiableMap(fields);
    }

    private static final String RECOMMENDATION =
            "Bind incoming request bodies to an explicit allow-list of fields the client is meant "
            + "to set (a dedicated request DTO, not the persisted entity itself), rather than "
            + "accepting and applying whatever properties a request happens to include.";

    private final SentinelHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ScanContext scanContext;

    public MassAssignmentScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "mass-assignment";
    }

    @Override
    public void beginScan(ScanContext context) {
        this.scanContext = context;
    }

    @Override
    public List<Finding> endScan() {
        this.scanContext = null;
        return List.of();
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        ScanIdentity identity = identityToUse();
        if (identity == null || !BODY_METHODS.contains(endpoint.method()) || endpoint.requestBodySample() == null) {
            return List.of();
        }

        JsonNode baseBody;
        try {
            baseBody = objectMapper.readTree(endpoint.requestBodySample());
        } catch (Exception e) {
            return List.of();
        }
        if (!baseBody.isObject()) {
            return List.of();
        }

        ObjectNode augmentedBody = ((ObjectNode) baseBody).deepCopy();
        Map<String, String> injectedValues = new LinkedHashMap<>();
        for (String field : CANDIDATE_FIELDS.keySet()) {
            if (augmentedBody.has(field)) {
                // Already a documented/legitimate input field - injecting over it would prove
                // nothing about undocumented binding, and could corrupt a value the request
                // otherwise needed to stay valid.
                continue;
            }
            String value = SampleValues.randomToken();
            augmentedBody.put(field, value);
            injectedValues.put(field, value);
        }
        if (injectedValues.isEmpty()) {
            return List.of();
        }

        HttpResponseData response;
        try {
            response = httpClient.exchange(endpoint.method(), endpoint.url(), Map.of(),
                    augmentedBody.toString(), Map.of(identity.header(), identity.value()));
        } catch (Exception e) {
            log.warn("Mass assignment check failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return List.of();
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            // Rejected outright, or throttled - neither is evidence either way. A 429 here just
            // means this check never really ran, same as every other module's throttle handling.
            return List.of();
        }

        JsonNode responseBody;
        try {
            responseBody = objectMapper.readTree(response.bodyOrEmpty());
        } catch (Exception e) {
            return List.of();
        }

        return injectedValues.entrySet().stream()
                .filter(entry -> containsFieldWithValue(responseBody, entry.getKey(), entry.getValue(), 0))
                .map(entry -> buildFinding(endpoint, entry.getKey(), entry.getValue()))
                .toList();
    }

    private Finding buildFinding(Endpoint endpoint, String field, String value) {
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.MASS_ASSIGNMENT,
                CANDIDATE_FIELDS.get(field),
                endpoint.url(),
                endpoint.method().name(),
                field,
                "",
                "An endpoint bound an undocumented, privilege/ownership-related field from the "
                        + "request body straight onto the created or updated resource.",
                "Sent '" + field + "' (not part of the endpoint's documented request body) with "
                        + "value '" + value + "' on " + endpoint.method() + " " + endpoint.url()
                        + "; the response echoed that exact field and value back, instead of "
                        + "ignoring or rejecting it.",
                RECOMMENDATION
        );
    }

    private ScanIdentity identityToUse() {
        if (scanContext == null) {
            return null;
        }
        return scanContext.identityA() != null ? scanContext.identityA() : scanContext.identityB();
    }

    /**
     * Same "search regardless of response envelope" approach as {@code IdorScanner}'s id lookup:
     * checks every object's own fields before recursing into nested ones, so this works whether
     * the created/updated resource comes back flat or wrapped (e.g. {@code {"data": {...}}}).
     */
    private boolean containsFieldWithValue(JsonNode node, String field, String expectedValue, int depth) {
        if (node == null || !node.isObject() || depth > MAX_JSON_SEARCH_DEPTH) {
            return false;
        }
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            if (field.equalsIgnoreCase(entry.getKey()) && entry.getValue().isValueNode()
                    && expectedValue.equals(entry.getValue().asText())) {
                return true;
            }
        }
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            if (containsFieldWithValue(entry.getValue(), field, expectedValue, depth + 1)) {
                return true;
            }
        }
        return false;
    }
}
