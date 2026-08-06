package com.f3rren.sentinel.attack.misconfig;

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

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Flags common security-relevant misconfigurations visible on an ordinary, successful response:
 * missing defense-in-depth headers, a CORS policy that reflects an arbitrary Origin (worse still
 * paired with credentials), and a Server/X-Powered-By banner that discloses implementation
 * details. None of this fuzzes anything - it inspects one legitimate GET (plus, for CORS, one
 * extra GET carrying a hostile Origin header) per endpoint, so unlike the other modules it is
 * read-only by construction and needs no ordering relative to state-mutating checks.
 */
@Component
@Order(3)
@ConditionalOnProperty(prefix = "sentinel.scan.security-misconfiguration", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityMisconfigurationScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(SecurityMisconfigurationScanner.class);

    // Deliberately nothing like a real origin this API would ever legitimately allow, so any
    // reflection of it back in Access-Control-Allow-Origin is unambiguous evidence that the
    // policy trusts whatever Origin the caller sends instead of checking against an allow-list.
    private static final String PROBE_ORIGIN = "https://sentinel-cors-probe.invalid";

    private static final String MISSING_HEADERS_RECOMMENDATION =
            "Set the missing security headers at the gateway level (or in a filter shared by all "
            + "services), so the protection is applied uniformly without repeating it in every "
            + "microservice: X-Content-Type-Options: nosniff, X-Frame-Options: DENY (or CSP with "
            + "frame-ancestors), Content-Security-Policy with a policy suited to the response type "
            + "(a JSON API can start from default-src 'none'), and Strict-Transport-Security if the "
            + "service is also exposed over HTTPS.";

    private static final String PERMISSIVE_CORS_RECOMMENDATION =
            "Replace the indiscriminate reflection of the Origin (or the '*' wildcard) with an "
            + "explicit allow-list of the domains actually authorized to call the API from a browser. "
            + "If requests need to carry credentials (cookies, Authorization header), "
            + "Access-Control-Allow-Origin cannot be '*' per the CORS spec: it must still be "
            + "restricted to trusted origins.";

    private static final String SERVER_BANNER_RECOMMENDATION =
            "Remove or obscure the header that exposes the server's technology/version (e.g. via "
            + "gateway or HTTP container configuration), so as not to make it easier for an attacker "
            + "to look up known CVEs for that specific version.";

    private final SentinelHttpClient httpClient;

    public SecurityMisconfigurationScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "security-misconfiguration";
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        if (!HttpMethod.GET.equals(endpoint.method())) {
            return List.of();
        }

        Map<String, String> params = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            params.put(param.name(), param.sampleValue());
        }

        HttpResponseData response;
        try {
            response = httpClient.exchange(endpoint.method(), endpoint.url(), params);
        } catch (Exception e) {
            log.warn("Security-misconfiguration check failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return List.of();
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();
        checkSecurityHeaders(endpoint, response).ifPresent(findings::add);
        checkBannerDisclosure(endpoint, response).ifPresent(findings::add);
        checkCors(endpoint).ifPresent(findings::add);
        return findings;
    }

    private Optional<Finding> checkSecurityHeaders(Endpoint endpoint, HttpResponseData response) {
        List<String> missing = new ArrayList<>();
        if (response.header("x-content-type-options").isEmpty()) {
            missing.add("X-Content-Type-Options");
        }
        if (response.header("x-frame-options").isEmpty()) {
            missing.add("X-Frame-Options");
        }
        if (response.header("content-security-policy").isEmpty()) {
            missing.add("Content-Security-Policy");
        }
        if (isHttps(endpoint.url()) && response.header("strict-transport-security").isEmpty()) {
            missing.add("Strict-Transport-Security");
        }

        if (missing.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.MISSING_SECURITY_HEADERS,
                Severity.LOW,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "The response does not include one or more recommended security headers.",
                "Missing headers on " + endpoint.method() + " " + endpoint.url() + ": " + String.join(", ", missing) + ".",
                MISSING_HEADERS_RECOMMENDATION
        ));
    }

    private Optional<Finding> checkCors(Endpoint endpoint) {
        HttpResponseData corsResponse;
        try {
            corsResponse = httpClient.getWithHeader(endpoint.url(), "Origin", PROBE_ORIGIN);
        } catch (Exception e) {
            log.warn("CORS probe failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return Optional.empty();
        }

        Optional<String> allowOrigin = corsResponse.header("access-control-allow-origin");
        if (allowOrigin.isEmpty()) {
            return Optional.empty();
        }
        String value = allowOrigin.get();
        boolean reflectsArbitraryOrigin = value.equals(PROBE_ORIGIN) || value.equals("*");
        if (!reflectsArbitraryOrigin) {
            return Optional.empty();
        }

        boolean allowsCredentials = corsResponse.header("access-control-allow-credentials")
                .map(v -> v.equalsIgnoreCase("true"))
                .orElse(false);
        Severity severity = allowsCredentials ? Severity.HIGH : Severity.MEDIUM;

        return Optional.of(new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.PERMISSIVE_CORS,
                severity,
                endpoint.url(),
                endpoint.method().name(),
                "Origin",
                PROBE_ORIGIN,
                "The CORS policy accepts an arbitrary Origin instead of an allow-list of trusted domains.",
                "Request with header 'Origin: " + PROBE_ORIGIN + "' on " + endpoint.method() + " " + endpoint.url()
                        + " received response 'Access-Control-Allow-Origin: " + value + "'"
                        + (allowsCredentials ? " together with 'Access-Control-Allow-Credentials: true'." : "."),
                PERMISSIVE_CORS_RECOMMENDATION
        ));
    }

    private Optional<Finding> checkBannerDisclosure(Endpoint endpoint, HttpResponseData response) {
        List<String> banners = new ArrayList<>();
        response.header("server").filter(SecurityMisconfigurationScanner::looksVersioned)
                .ifPresent(v -> banners.add("Server: " + v));
        response.header("x-powered-by").ifPresent(v -> banners.add("X-Powered-By: " + v));

        if (banners.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.SERVER_BANNER_DISCLOSURE,
                Severity.LOW,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "The response discloses the server's technology and/or version via HTTP headers.",
                "Headers detected on " + endpoint.method() + " " + endpoint.url() + ": " + String.join(", ", banners) + ".",
                SERVER_BANNER_RECOMMENDATION
        ));
    }

    private static boolean looksVersioned(String serverHeaderValue) {
        return serverHeaderValue.chars().anyMatch(Character::isDigit);
    }

    private static boolean isHttps(String url) {
        try {
            return "https".equalsIgnoreCase(URI.create(url).getScheme());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
