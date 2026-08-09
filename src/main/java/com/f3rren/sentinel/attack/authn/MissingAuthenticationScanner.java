package com.f3rren.sentinel.attack.authn;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Flags endpoints that return a successful response to a request carrying no credentials at
 * all - Sentinel never sends an Authorization header, so any 2xx response here means the
 * endpoint accepted the call from a fully anonymous caller. A 401/403 is treated as evidence
 * that authentication IS enforced (not a finding); any other status (400/404/415/5xx - often
 * caused by Sentinel's own baseline request not matching what the endpoint expects, e.g. a
 * missing JSON body) is inconclusive and silently skipped, since we genuinely don't know
 * whether auth would have blocked it.
 * <p>
 * This is deliberately narrower than full IDOR/BOLA testing, which needs two distinct
 * authenticated identities to compare access to the same resource - not a concept Sentinel has
 * yet. It only answers "does this endpoint require authentication at all", which is still a
 * meaningful, cheap-to-check signal on its own.
 */
@Component
@Order(1)
@ConditionalOnProperty(prefix = "sentinel.scan.missing-authentication", name = "enabled", havingValue = "true", matchIfMissing = true)
public class MissingAuthenticationScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(MissingAuthenticationScanner.class);

    private static final Set<HttpMethod> MUTATING_METHODS =
            Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE);

    private static final String RECOMMENDATION =
            "Require authentication (e.g. OAuth2/JWT) on this endpoint and verify that the authenticated "
            + "identity is authorized on the specific resource requested (ownership check), not just that "
            + "it is generically logged in. Apply the same policy consistently across every service "
            + "behind the gateway, not only the most visible ones.";

    private final SentinelHttpClient httpClient;

    public MissingAuthenticationScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "missing-authentication";
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        Map<String, String> baselineParams = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            baselineParams.put(param.name(), param.sampleValue());
        }

        HttpResponseData response;
        try {
            response = httpClient.exchange(endpoint.method(), endpoint.url(), baselineParams, endpoint.requestBodySample());
        } catch (Exception e) {
            log.warn("Missing-authentication check failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return List.of();
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return List.of();
        }

        Severity severity = MUTATING_METHODS.contains(endpoint.method()) ? Severity.HIGH : Severity.MEDIUM;
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.MISSING_AUTHENTICATION,
                severity,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "The endpoint responded successfully to a request carrying no credentials at all.",
                "Status " + response.statusCode() + " on " + endpoint.method() + " " + endpoint.url()
                        + " without an authentication header.",
                RECOMMENDATION
        );
        return List.of(finding);
    }
}
