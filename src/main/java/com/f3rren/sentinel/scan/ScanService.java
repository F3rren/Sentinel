package com.f3rren.sentinel.scan;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.discovery.EndpointDiscoveryService;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.report.ReportGenerator;
import com.f3rren.sentinel.web.exception.InvalidTargetException;
import com.f3rren.sentinel.web.exception.ScanNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Orchestrates a scan end to end: discover candidate endpoints on the target, run every
 * registered attack module against each of them, and compile the findings into a report.
 * Runs synchronously - acceptable for the shallow single-page discovery this first version
 * performs; reports are kept in memory for later retrieval by id.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final EndpointDiscoveryService discoveryService;
    private final List<AttackModule> attackModules;
    private final ReportGenerator reportGenerator;
    private final int maxEndpoints;
    private final Map<String, ScanReport> reports = new ConcurrentHashMap<>();

    public ScanService(
            EndpointDiscoveryService discoveryService,
            List<AttackModule> attackModules,
            ReportGenerator reportGenerator,
            @Value("${sentinel.scan.max-endpoints:25}") int maxEndpoints
    ) {
        this.discoveryService = discoveryService;
        this.attackModules = attackModules;
        this.reportGenerator = reportGenerator;
        this.maxEndpoints = maxEndpoints;
    }

    public ScanReport runScan(String rawTargetUrl) {
        String targetUrl = normalizeTargetUrl(rawTargetUrl);
        Instant startedAt = Instant.now();

        List<Endpoint> endpoints = discoveryService.discover(targetUrl);
        List<Endpoint> endpointsToScan = endpoints.size() > maxEndpoints
                ? endpoints.subList(0, maxEndpoints)
                : endpoints;

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
        ScanReport report = reportGenerator.buildReport(id, targetUrl, startedAt, finishedAt, endpoints.size(), findings);
        reports.put(id, report);
        return report;
    }

    public ScanReport getReport(String id) {
        ScanReport report = reports.get(id);
        if (report == null) {
            throw new ScanNotFoundException(id);
        }
        return report;
    }

    private String normalizeTargetUrl(String rawTargetUrl) {
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
