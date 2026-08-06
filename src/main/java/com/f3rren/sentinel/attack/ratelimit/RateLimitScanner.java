package com.f3rren.sentinel.attack.ratelimit;

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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Fires a burst of back-to-back requests at a single {@code GET} endpoint and checks whether
 * the target ever responds with a throttling status (429 Too Many Requests, 423 Locked). If it
 * never does across the whole burst, reports {@link VulnerabilityType#MISSING_RATE_LIMITING}
 * (LOW) - worded cautiously, same as the brute-force module's missing-protection finding: a
 * fixed burst not tripping a limit doesn't prove no limit exists at a higher threshold or a
 * different time window.
 * <p>
 * {@code GET}-only and read-only by construction (no state-changing verb is ever bursted): the
 * whole point is a rapid, repeated request, which would amplify the effect of a single POST/PUT
 * far more than the one-off calls the other modules make.
 * <p>
 * Ordered to run strictly after every other module ({@link Order} with the highest value among
 * them - see {@code ScanService}, which runs each module across every endpoint before moving to
 * the next): a shared, per-IP rate-limit bucket (a common real-world design, not specific to any
 * one target) covers every route, not just the one being bursted. Running this module first
 * would burn through that shared budget early and starve every other module's later requests to
 * unrelated endpoints of a clean, unthrottled response - turning their real findings (e.g. a
 * genuinely unauthenticated endpoint) into false negatives (a 429 that gets read as
 * inconclusive) purely as a side effect of this module's own traffic.
 */
@Component
@Order(4)
@ConditionalOnProperty(prefix = "sentinel.scan.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = true)
public class RateLimitScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(RateLimitScanner.class);

    private static final String RECOMMENDATION =
            "Implementare un meccanismo di rate-limiting (es. token bucket per IP/utente/API key) "
            + "su questo endpoint, per prevenire abusi come scraping massivo, esaurimento di "
            + "risorse (DoS applicativo) o uso ripetuto e automatizzato della logica di business.";

    private final SentinelHttpClient httpClient;
    private final int burstSize;

    public RateLimitScanner(SentinelHttpClient httpClient,
            @Value("${sentinel.scan.rate-limit.burst-size:20}") int burstSize) {
        this.httpClient = httpClient;
        this.burstSize = burstSize;
    }

    @Override
    public String name() {
        return "rate-limit";
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

        for (int i = 0; i < burstSize; i++) {
            HttpResponseData response;
            try {
                response = httpClient.exchange(endpoint.method(), endpoint.url(), params);
            } catch (Exception e) {
                log.warn("Rate-limit burst request failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
                return List.of();
            }
            if (SentinelHttpClient.THROTTLE_STATUS_CODES.contains(response.statusCode())) {
                // Rate limiting is present and reacted within the burst: nothing to report.
                return List.of();
            }
        }

        return List.of(missingRateLimitingFinding(endpoint));
    }

    private Finding missingRateLimitingFinding(Endpoint endpoint) {
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.MISSING_RATE_LIMITING,
                Severity.LOW,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "L'endpoint non ha mai risposto con un blocco/limite dopo richieste ravvicinate ripetute.",
                burstSize + " richieste consecutive senza mai ricevere uno status 429 (Too Many Requests) "
                        + "o 423 (Locked). Un numero di richieste più alto o una finestra temporale diversa "
                        + "potrebbero comunque attivare una protezione non ancora raggiunta da questo campione.",
                RECOMMENDATION
        );
    }
}
