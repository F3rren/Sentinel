package com.f3rren.sentinel.attack.actuator;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Probes a small, fixed set of Spring Boot Actuator endpoint IDs that disclose internal
 * application state (environment variables, a full heap dump, bean graph, ...) when exposed
 * without authentication - one of the concrete examples behind Security Misconfiguration in
 * OWASP's 2025 Top 10. Unlike {@link com.f3rren.sentinel.attack.misconfig.SecurityMisconfigurationScanner},
 * which inspects headers on every discovered endpoint's own response, this checks host-level
 * paths that have nothing to do with any specific discovered endpoint - so it only needs to run
 * once per scan (against the origin of whichever endpoint it sees first), not once per endpoint.
 * <p>
 * Detection is a plain GET per candidate path: a 2xx status with an actuator-shaped
 * {@code Content-Type} (JSON, the actuator vendor media type, or {@code application/octet-stream}
 * for {@code heapdump}) is treated as exposed. The content-type check exists specifically to
 * avoid false positives on a target that answers every unknown path with 200 (e.g. an SPA
 * catch-all serving {@code index.html}). Response bodies are never included in a finding's
 * evidence - only the probed path and its outcome - so this can't turn the report itself into a
 * copy of whatever it just found exposed.
 */
@Component
@Order(7)
@ConditionalOnProperty(prefix = "sentinel.scan.actuator-exposure", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ActuatorExposureScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(ActuatorExposureScanner.class);

    private static final Map<String, Severity> SENSITIVE_ACTUATOR_PATHS;

    static {
        Map<String, Severity> paths = new LinkedHashMap<>();
        // Full environment (system properties, env vars, config sources) - frequently includes
        // secrets under a property name Spring's own sanitizer doesn't recognize - CRITICAL.
        paths.put("env", Severity.CRITICAL);
        // A raw JVM heap dump: whatever was in memory when it was taken, credentials included -
        // CRITICAL.
        paths.put("heapdump", Severity.CRITICAL);
        // The application's fully-resolved configuration properties - HIGH.
        paths.put("configprops", Severity.HIGH);
        // Recent HTTP request/response exchanges, potentially including auth headers or session
        // data depending on what's configured to be recorded - HIGH.
        paths.put("httpexchanges", Severity.HIGH);
        // Internal architecture disclosure (bean graph, routing table, thread state) - useful
        // recon for further attacks but not a direct data leak - MEDIUM.
        paths.put("beans", Severity.MEDIUM);
        paths.put("mappings", Severity.MEDIUM);
        paths.put("threaddump", Severity.MEDIUM);
        // Logger configuration only - LOW.
        paths.put("loggers", Severity.LOW);
        SENSITIVE_ACTUATOR_PATHS = Collections.unmodifiableMap(paths);
    }

    private static final String RECOMMENDATION =
            "Restrict management.endpoints.web.exposure.include to only the endpoints actually "
            + "needed at runtime (health, info and metrics are usually enough) instead of a "
            + "wildcard or a broad list. Any operational endpoint that must stay available (env, "
            + "heapdump, beans, mappings, threaddump, loggers, configprops, httpexchanges) should "
            + "sit behind its own authentication and be reachable only from a private management "
            + "network - never on the same publicly exposed port as the application.";

    private final SentinelHttpClient httpClient;

    // Actuator exposure is a host-level property, not a per-endpoint one: probing it again for
    // every discovered endpoint would just repeat the exact same requests. This flag makes the
    // check fire once per scan instead. Modules are singleton beans shared across every scan
    // Sentinel ever runs, so it must be reset in beginScan - never left set from a previous scan.
    private boolean checked;

    public ActuatorExposureScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "actuator-exposure";
    }

    @Override
    public void beginScan(ScanContext context) {
        checked = false;
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        if (checked) {
            return List.of();
        }
        checked = true;

        String origin = originOf(endpoint.url());
        if (origin == null) {
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, Severity> candidate : SENSITIVE_ACTUATOR_PATHS.entrySet()) {
            String path = candidate.getKey();
            String url = origin + "/actuator/" + path;
            HttpResponseData response;
            try {
                response = httpClient.get(url);
            } catch (Exception e) {
                log.debug("Actuator probe failed for {}: {}", url, e.getMessage());
                continue;
            }
            if (isExposed(response)) {
                findings.add(buildFinding(url, path, candidate.getValue()));
            }
        }
        return findings;
    }

    private boolean isExposed(HttpResponseData response) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return false;
        }
        return response.header("content-type")
                .map(ct -> {
                    String value = ct.toLowerCase(java.util.Locale.ROOT);
                    return value.contains("json") || value.contains("actuator") || value.contains("octet-stream");
                })
                .orElse(false);
    }

    private static String originOf(String url) {
        try {
            URI uri = URI.create(url);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            String portSuffix = uri.getPort() == -1 ? "" : ":" + uri.getPort();
            return uri.getScheme() + "://" + uri.getHost() + portSuffix;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Finding buildFinding(String url, String path, Severity severity) {
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.EXPOSED_ACTUATOR_ENDPOINT,
                severity,
                url,
                "GET",
                path,
                "",
                "The Spring Boot Actuator endpoint '/actuator/" + path + "' is reachable without "
                        + "authentication and discloses internal application state.",
                "GET " + url + " returned a successful response with actuator-shaped content - the "
                        + "response body itself is not included in this report.",
                RECOMMENDATION
        );
    }
}
