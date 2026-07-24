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
    private final Path reportsDirectory;

    public ReportFileWriter(
            ObjectMapper objectMapper,
            @Value("${sentinel.scan.reports-directory:reports}") String reportsDirectoryRaw
    ) {
        this.objectMapper = objectMapper;
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
            Path target = reportsDirectory.resolve(buildFileName(report));
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), report);
            log.info("Report salvato in {}", target.toAbsolutePath());
        } catch (Exception e) {
            log.warn("Impossibile salvare su file il report {}: {}", report.id(), e.getMessage());
        }
    }

    private String buildFileName(ScanReport report) {
        String timestamp = FILENAME_TIMESTAMP.format(report.startedAt());
        return timestamp + "-" + safeHost(report.targetUrl()) + "-" + report.id() + ".json";
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
