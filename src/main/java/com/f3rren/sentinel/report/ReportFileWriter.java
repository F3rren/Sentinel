package com.f3rren.sentinel.report;

import com.f3rren.sentinel.model.ScanReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Persists every completed scan as a JSON file inside the project's working directory, in
 * addition to the in-memory store the REST API reads from - so a report survives an app
 * restart and can be reviewed, diffed against an earlier run, or committed alongside the code
 * it was run against, without needing to remember its id.
 * <p>
 * Best-effort: a failure to write the file is logged and never fails the scan itself, since the
 * caller already has the report back from the API regardless.
 */
@Component
public class ReportFileWriter {

    private static final Logger log = LoggerFactory.getLogger(ReportFileWriter.class);
    private static final DateTimeFormatter FILENAME_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

    private final ObjectMapper objectMapper;
    private final SarifConverter sarifConverter;
    private final Path reportsDirectory;

    public ReportFileWriter(
            ObjectMapper objectMapper,
            SarifConverter sarifConverter,
            @Value("${sentinel.scan.reports-directory:reports}") String reportsDirectoryRaw
    ) {
        this.objectMapper = objectMapper;
        this.sarifConverter = sarifConverter;
        this.reportsDirectory = (reportsDirectoryRaw == null || reportsDirectoryRaw.isBlank())
                ? null
                : Path.of(reportsDirectoryRaw);
    }

    public void write(ScanReport report) {
        if (reportsDirectory == null) {
            return;
        }
        try {
            Files.createDirectories(reportsDirectory);
            String baseName = buildBaseName(report);

            Path jsonTarget = reportsDirectory.resolve(baseName + ".json");
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(jsonTarget.toFile(), report);

            // The same report as SARIF, alongside the JSON, so a CI step can upload it to GitHub
            // code scanning without any conversion of its own.
            Path sarifTarget = reportsDirectory.resolve(baseName + ".sarif");
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(sarifTarget.toFile(), sarifConverter.toSarif(report));

            log.info("Report saved to {} (+ .sarif)", jsonTarget.toAbsolutePath());
        } catch (Exception e) {
            log.warn("Failed to save report {} to file: {}", report.id(), e.getMessage());
        }
    }

    private String buildBaseName(ScanReport report) {
        String timestamp = FILENAME_TIMESTAMP.format(report.startedAt());
        return timestamp + "-" + safeHost(report.targetUrl()) + "-" + report.id();
    }

    private String safeHost(String targetUrl) {
        try {
            String host = URI.create(targetUrl).getHost();
            return (host == null ? "target" : host).replaceAll("[^a-zA-Z0-9.-]", "_");
        } catch (IllegalArgumentException e) {
            return "target";
        }
    }
}
