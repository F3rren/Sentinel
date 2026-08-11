package com.f3rren.sentinel.attack.bfla;

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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Checks for Broken Function Level Authorization (BFLA): whether an endpoint whose path
 * suggests a privileged/administrative function (e.g. containing "admin", "internal",
 * "management") is actually reachable by an ordinary authenticated identity, rather than
 * being restricted to a genuinely elevated role.
 * <p>
 * Unlike the IDOR module, this doesn't need to compare two identities against each other:
 * proving broken function-level authorization only requires showing that <em>some</em> regular,
 * non-privileged identity can reach a function that looks like it should require more than
 * "logged in at all". So it reuses whichever identities a scan happens to supply (see
 * {@code POST /api/scans}' {@code identities} field) purely as "a real authenticated caller",
 * not to compare ownership the way IDOR does - identity A is tried first, identity B only if A
 * was denied (or the check was inconclusive), and at most one finding is reported per endpoint
 * regardless of how many identities would have revealed it.
 * <p>
 * Detection is a heuristic on the URL path, not real insight into the target's permission
 * model - Sentinel has no general way to know that. A match means "worth a human's attention",
 * not a certainty. Kept deliberately small and conservative (a short, unambiguous keyword
 * list) to limit false positives rather than guessing broadly.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
@ConditionalOnProperty(prefix = "sentinel.scan.bfla", name = "enabled", havingValue = "true", matchIfMissing = false)
public class BflaScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(BflaScanner.class);

    private static final Set<HttpMethod> MUTATING_METHODS =
            Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE);

    private static final List<String> PRIVILEGED_PATH_KEYWORDS = List.of("admin", "internal", "management");

    private static final String RECOMMENDATION =
            "Verify server-side, on every request to a privileged or administrative function, "
            + "that the caller's role or permission level actually grants access - not just "
            + "that they are generically authenticated. Deny by default (403) when the role "
            + "check is missing or fails, rather than allowing by default.";

    private final SentinelHttpClient httpClient;
    private ScanContext scanContext;

    public BflaScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "bfla";
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
        if (scanContext == null || !scanContext.hasBothIdentities()) {
            return List.of();
        }
        String matchedKeyword = matchedKeyword(endpoint.url());
        if (matchedKeyword == null) {
            return List.of();
        }

        return checkIdentity(endpoint, scanContext.identityA(), matchedKeyword)
                .or(() -> checkIdentity(endpoint, scanContext.identityB(), matchedKeyword))
                .map(List::of)
                .orElseGet(List::of);
    }

    private Optional<Finding> checkIdentity(Endpoint endpoint, ScanIdentity identity, String matchedKeyword) {
        HttpResponseData response;
        try {
            response = httpClient.exchange(endpoint.method(), endpoint.url(), paramsOf(endpoint),
                    endpoint.requestBodySample(), Map.of(identity.header(), identity.value()));
        } catch (Exception e) {
            log.warn("BFLA check failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return Optional.empty();
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            // Denied, or inconclusive (e.g. throttled) - neither is evidence of a broken check.
            return Optional.empty();
        }

        Severity severity = MUTATING_METHODS.contains(endpoint.method()) ? Severity.CRITICAL : Severity.HIGH;
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.BFLA,
                severity,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "An endpoint whose path suggests a privileged/administrative function is reachable by an ordinary authenticated identity.",
                "The URL path contains '" + matchedKeyword + "', suggesting restricted access, but a regular "
                        + "authenticated identity received status " + response.statusCode() + " on "
                        + endpoint.method() + " " + endpoint.url() + " instead of a 401/403 denial.",
                RECOMMENDATION
        );
        return Optional.of(finding);
    }

    private Map<String, String> paramsOf(Endpoint endpoint) {
        Map<String, String> params = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            params.put(param.name(), param.sampleValue());
        }
        return params;
    }

    /**
     * Case-insensitive substring match against the URL's path only (not its query string, host,
     * or scheme) so a keyword appearing incidentally in a parameter value can't cause a false
     * match.
     */
    private String matchedKeyword(String url) {
        String path;
        try {
            path = URI.create(url).getPath().toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
        for (String keyword : PRIVILEGED_PATH_KEYWORDS) {
            if (path.contains(keyword)) {
                return keyword;
            }
        }
        return null;
    }
}
