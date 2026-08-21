package com.f3rren.sentinel.web;

import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.ScanIdentity;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.report.SarifConverter;
import com.f3rren.sentinel.scan.ScanService;
import com.f3rren.sentinel.web.dto.IdentitiesRequest;
import com.f3rren.sentinel.web.dto.IdentityRequest;
import com.f3rren.sentinel.web.dto.ScanRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.node.ObjectNode;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;
    private final SarifConverter sarifConverter;

    public ScanController(ScanService scanService, SarifConverter sarifConverter) {
        this.scanService = scanService;
        this.sarifConverter = sarifConverter;
    }

    @PostMapping
    public ResponseEntity<ScanReport> startScan(@Valid @RequestBody ScanRequest request) {
        ScanReport report = scanService.runScan(request.targetUrl(), toScanContext(request.identities()));
        return ResponseEntity.status(HttpStatus.CREATED).body(report);
    }

    private ScanContext toScanContext(IdentitiesRequest identities) {
        if (identities == null) {
            return ScanContext.EMPTY;
        }
        return new ScanContext(toScanIdentity(identities.a()), toScanIdentity(identities.b()));
    }

    private ScanIdentity toScanIdentity(IdentityRequest identity) {
        return identity != null ? new ScanIdentity(identity.header(), identity.value()) : null;
    }

    @GetMapping("/latest")
    public ScanReport getLatestScan() {
        return scanService.getLatestReport();
    }

    @GetMapping("/{id}")
    public ScanReport getScan(@PathVariable String id) {
        return scanService.getReport(id);
    }

    /** The most recent scan as SARIF 2.1.0, ready to upload to GitHub code scanning. */
    @GetMapping("/latest/sarif")
    public ObjectNode getLatestScanSarif() {
        return sarifConverter.toSarif(scanService.getLatestReport());
    }

    /** A specific scan as SARIF 2.1.0, ready to upload to GitHub code scanning. */
    @GetMapping("/{id}/sarif")
    public ObjectNode getScanSarif(@PathVariable String id) {
        return sarifConverter.toSarif(scanService.getReport(id));
    }
}
