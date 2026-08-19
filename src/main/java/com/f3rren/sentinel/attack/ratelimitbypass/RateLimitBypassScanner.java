package com.f3rren.sentinel.attack.ratelimitbypass;

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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Checks whether a rate limit that genuinely triggers (see {@link
 * com.f3rren.sentinel.attack.ratelimit.RateLimitScanner}) can be trivially evaded by rotating a
 * client-supplied header - a common real-world mistake where the limiter keys its bucket off
 * {@code X-Forwarded-For} (or a similar header) instead of the actual TCP connection's remote
 * address, on the mistaken assumption that every deployment sits behind a trusted reverse proxy
 * that sets it itself.
 * <p>
 * Bursts a single {@code GET} endpoint with no extra headers until throttled (429/423) - exactly
 * {@link com.f3rren.sentinel.attack.ratelimit.RateLimitScanner}'s own burst, reused as the setup
 * for this check rather than a separate concern - then repeats the same request once per
 * candidate header, each time with a fresh, obviously-synthetic IP (the RFC 5737 {@code
 * 203.0.113.0/24} documentation range) as its value. A request that stops being throttled purely
 * because of that header is proof the bucket is keyed by attacker-controlled input.
 * <p>
 * Ordered to run immediately after {@code RateLimitScanner} for the same reason that module runs
 * last among every other one: both deliberately burst a shared, per-IP bucket, so they need to run
 * back-to-back at the very end, not interleaved with single-request checks that would otherwise be
 * starved of a clean response.
 */
@Component
@Order(10)
@ConditionalOnProperty(prefix = "sentinel.scan.rate-limit-bypass", name = "enabled", havingValue = "true", matchIfMissing = true)
public class RateLimitBypassScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(RateLimitBypassScanner.class);

    // Headers a naive rate limiter might mistakenly trust as the caller's real address instead of
    // the TCP connection's actual remote address.
    private static final List<String> SPOOFABLE_HEADERS = List.of(
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP"
    );

    private static final String RECOMMENDATION =
            "Key rate-limit buckets off the actual TCP connection's remote address, never a "
            + "client-supplied header (X-Forwarded-For, X-Real-IP, ...) - unless the request "
            + "genuinely arrives through a trusted reverse proxy that sets that header itself, in "
            + "which case the proxy must strip/overwrite any value the original client tried to "
            + "set before it ever reaches the application.";

    private final SentinelHttpClient httpClient;
    private final int burstSize;
    private final SecureRandom random = new SecureRandom();

    public RateLimitBypassScanner(SentinelHttpClient httpClient,
            @Value("${sentinel.scan.rate-limit.burst-size:20}") int burstSize) {
        this.httpClient = httpClient;
        this.burstSize = burstSize;
    }

    @Override
    public String name() {
        return "rate-limit-bypass";
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

        if (!establishThrottling(endpoint, params)) {
            // Never got throttled at all within the burst - nothing to bypass. RateLimitScanner
            // is the one that reports that absence; this module has nothing to add here.
            return List.of();
        }

        for (String header : SPOOFABLE_HEADERS) {
            String spoofedIp = randomDocumentationIp();
            HttpResponseData response;
            try {
                response = httpClient.exchange(endpoint.method(), endpoint.url(), params, null, Map.of(header, spoofedIp));
            } catch (Exception e) {
                log.warn("Rate-limit bypass probe failed for {} {} with header {}: {}",
                        endpoint.method(), endpoint.url(), header, e.getMessage());
                continue;
            }
            if (!SentinelHttpClient.THROTTLE_STATUS_CODES.contains(response.statusCode())) {
                return List.of(bypassFinding(endpoint, header, spoofedIp));
            }
        }
        return List.of();
    }

    /**
     * @return true once a throttled response is observed within the burst, false if the whole
     * burst completes without ever being throttled.
     */
    private boolean establishThrottling(Endpoint endpoint, Map<String, String> params) {
        for (int i = 0; i < burstSize; i++) {
            HttpResponseData response;
            try {
                response = httpClient.exchange(endpoint.method(), endpoint.url(), params);
            } catch (Exception e) {
                log.warn("Rate-limit bypass baseline request failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
                return false;
            }
            if (SentinelHttpClient.THROTTLE_STATUS_CODES.contains(response.statusCode())) {
                return true;
            }
        }
        return false;
    }

    private String randomDocumentationIp() {
        return "203.0.113." + (1 + random.nextInt(254));
    }

    private Finding bypassFinding(Endpoint endpoint, String header, String spoofedIp) {
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.RATE_LIMIT_BYPASS,
                Severity.HIGH,
                endpoint.url(),
                endpoint.method().name(),
                header,
                spoofedIp,
                "The rate limit that throttled repeated requests stopped applying as soon as a "
                        + "client-supplied header changed, indicating the limiter keys its bucket off "
                        + "that header instead of the real client address.",
                "After being throttled by repeated requests to " + endpoint.method() + " " + endpoint.url()
                        + " with no extra headers, the identical request succeeded again once '" + header
                        + ": " + spoofedIp + "' was added - an attacker fully controls this header and can "
                        + "set a fresh value on every request to bypass the limit entirely.",
                RECOMMENDATION
        );
    }
}
