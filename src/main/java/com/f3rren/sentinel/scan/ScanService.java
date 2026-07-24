package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.discovery.EndpointDiscoveryService;
import com.f3rren.sentinel.discovery.openapi.OpenApiDiscoveryResult;
import com.f3rren.sentinel.discovery.openapi.OpenApiDiscoveryService;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.report.ReportGenerator;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import com.f3rren.sentinel.web.exception.ScanNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Orchestrates a scan end to end: discover candidate endpoints on the target, run every
 * registered attack module against each of them, and compile the findings into a report.
 * Runs synchronously - acceptable for the shallow single-page discovery this first version
 * performs; reports are kept in memory for later retrieval by id.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private static final Set<HttpMethod> DEFAULT_ALLOWED_METHODS =
            Set.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE);

    private final OpenApiDiscoveryService openApiDiscoveryService;
    private final EndpointDiscoveryService discoveryService;
    private final List<AttackModule> attackModules;
    private final ReportGenerator reportGenerator;
    private final int maxEndpoints;
    private final Set<HttpMethod> allowedHttpMethods;
    private final Map<String, ScanReport> reports = new ConcurrentHashMap<>();
    private final AtomicReference<String> latestReportId = new AtomicReference<>();

    public ScanService(
            OpenApiDiscoveryService openApiDiscoveryService,
            EndpointDiscoveryService discoveryService,
            // Every attack module can be individually disabled (sentinel.scan.<module>.enabled=false),
            // so this list can legitimately be empty - not required, or Spring refuses to start the
            // whole app the moment someone disables the only module that happens to exist.
            @Autowired(required = false) List<AttackModule> attackModules,
            ReportGenerator reportGenerator,
            @Value("${sentinel.scan.max-endpoints:25}") int maxEndpoints,
            @Value("${sentinel.scan.allowed-http-methods:GET,POST,PUT,PATCH,DELETE}") String allowedHttpMethodsRaw
    ) {
        this.openApiDiscoveryService = openApiDiscoveryService;
        this.discoveryService = discoveryService;
        this.attackModules = attackModules != null ? attackModules : List.of();
        this.reportGenerator = reportGenerator;
        this.maxEndpoints = maxEndpoints;
        this.allowedHttpMethods = parseAllowedMethods(allowedHttpMethodsRaw);
    }

    // HttpMethod is no longer a plain enum in Spring 7: HttpMethod.valueOf(String) happily
    // builds a custom instance for any string instead of throwing on an unknown one (it exists
    // to support non-standard verbs), so validation has to check against a known whitelist
    // ourselves rather than relying on an exception that will never come.
    private static final Set<String> KNOWN_METHOD_NAMES =
            Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE");

    private Set<HttpMethod> parseAllowedMethods(String raw) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT_ALLOWED_METHODS;
        }
        Set<HttpMethod> methods = new HashSet<>();
        for (String token : raw.split(",")) {
            String candidate = token.trim().toUpperCase();
            if (candidate.isEmpty()) {
                continue;
            }
            if (!KNOWN_METHOD_NAMES.contains(candidate)) {
                log.warn("Ignoro metodo HTTP sconosciuto in sentinel.scan.allowed-http-methods: '{}'", candidate);
                continue;
            }
            methods.add(HttpMethod.valueOf(candidate));
        }
        if (methods.isEmpty()) {
            log.warn("sentinel.scan.allowed-http-methods='{}' non contiene alcun metodo valido: uso il default ({}).",
                    raw, DEFAULT_ALLOWED_METHODS);
            return DEFAULT_ALLOWED_METHODS;
        }
        return methods;
    }

    public ScanReport runScan(String rawTargetUrl) {
        String targetUrl = normalizeTargetUrl(rawTargetUrl);
        Instant startedAt = Instant.now();

        // OpenAPI/Swagger is the preferred source: when the target exposes one, it enumerates
        // the real API surface (including endpoints no link ever points to) far more reliably
        // than crawling HTML. The HTML crawl still runs to pick up anything Swagger doesn't
        // cover (e.g. a plain login form) and its results are merged in, deduplicated.
        Optional<OpenApiDiscoveryResult> openApi = openApiDiscoveryService.discover(targetUrl);
        List<Endpoint> endpoints = new ArrayList<>(openApi.map(OpenApiDiscoveryResult::endpoints).orElseGet(List::of));
        for (Endpoint crawled : discoveryService.discover(targetUrl)) {
            boolean alreadyKnown = endpoints.stream()
                    .anyMatch(e -> e.method() == crawled.method() && e.url().equals(crawled.url()));
            if (!alreadyKnown) {
                endpoints.add(crawled);
            }
        }
        String openApiSpecUrl = openApi.map(OpenApiDiscoveryResult::specUrl).orElse(null);

        // Filter by allowed HTTP method before capping to maxEndpoints, so the cap is spent
        // entirely on endpoints that will actually be attacked instead of being wasted on ones
        // the method filter would have excluded anyway.
        List<Endpoint> methodFiltered = endpoints.stream()
                .filter(endpoint -> allowedHttpMethods.contains(endpoint.method()))
                .toList();
        List<Endpoint> endpointsToScan = methodFiltered.size() > maxEndpoints
                ? methodFiltered.subList(0, maxEndpoints)
                : methodFiltered;

        List<Finding> findings = new ArrayList<>();
        for (Endpoint endpoint : endpointsToScan) {
            for (AttackModule module : attackModules) {
                try {
                    findings.addAll(module.scan(endpoint));
                } catch (Exception e) {
                    log.warn("Attack module {} failed on {} {}: {}", module.name(), endpoint.method(), endpoint.url(), e.getMessage());
                }
            }
        }

        Instant finishedAt = Instant.now();
        String id = UUID.randomUUID().toString();
        ScanReport report = reportGenerator.buildReport(id, targetUrl, startedAt, finishedAt,
                endpoints.size(), endpointsToScan.size(), openApiSpecUrl, findings);
        reports.put(id, report);
        latestReportId.set(id);
        return report;
    }

    public ScanReport getReport(String id) {
        ScanReport report = reports.get(id);
        if (report == null) {
            throw new ScanNotFoundException(id);
        }
        return report;
    }

    /**
     * The report of the most recently completed scan, regardless of who triggered it - lets a
     * caller check the outcome of an automatic startup scan without first learning its id.
     */
    public ScanReport getLatestReport() {
        String id = latestReportId.get();
        if (id == null) {
            throw new ScanNotFoundException("latest");
        }
        return getReport(id);
    }

    public String normalizeTargetUrl(String rawTargetUrl) {
        if (rawTargetUrl == null || rawTargetUrl.isBlank()) {
            throw new InvalidTargetException("targetUrl non puo' essere vuoto");
        }
        String candidate = rawTargetUrl.trim();
        if (!candidate.startsWith("http://") && !candidate.startsWith("https://")) {
            candidate = "http://" + candidate;
        }
        URI uri;
        try {
            uri = URI.create(candidate);
        } catch (IllegalArgumentException e) {
            throw new InvalidTargetException("targetUrl non valido: " + rawTargetUrl);
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new InvalidTargetException("targetUrl non valido, host mancante: " + rawTargetUrl);
        }
        return candidate;
    }
}
