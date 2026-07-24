package com.f3rren.sentinel.web;

import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.scan.ScanService;
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

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping
    public ResponseEntity<ScanReport> startScan(@Valid @RequestBody ScanRequest request) {
        ScanReport report = scanService.runScan(request.targetUrl());
        return ResponseEntity.status(HttpStatus.CREATED).body(report);
    }

    @GetMapping("/latest")
    public ScanReport getLatestScan() {
        return scanService.getLatestReport();
    }

    @GetMapping("/{id}")
    public ScanReport getScan(@PathVariable String id) {
        return scanService.getReport(id);
    }
}
