package com.f3rren.sentinel.report;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Uses the real Spring-configured ObjectMapper bean (not a bare `new ObjectMapper()`) so this
 * exercises the exact serialization ReportFileWriter runs with in production, including
 * java.time.Instant handling.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class ReportFileWriterTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void writesReportAsJsonFileNamedWithTimestampHostAndId(@TempDir Path tempDir) throws IOException {
        Path reportsDir = tempDir.resolve("reports");
        ReportFileWriter writer = new ReportFileWriter(objectMapper, reportsDir.toString());
        ScanReport report = sampleReport();

        writer.write(report);

        try (Stream<Path> files = Files.list(reportsDir)) {
            List<Path> written = files.toList();
            assertThat(written).hasSize(1);
            String fileName = written.get(0).getFileName().toString();
            assertThat(fileName).endsWith(report.id() + ".json");
            assertThat(fileName).contains("localhost");

            ScanReport reloaded = objectMapper.readValue(written.get(0).toFile(), ScanReport.class);
            assertThat(reloaded.id()).isEqualTo(report.id());
            assertThat(reloaded.targetUrl()).isEqualTo(report.targetUrl());
            assertThat(reloaded.summary().riskScore()).isEqualTo(report.summary().riskScore());
        }
    }

    @Test
    void doesNothingWhenReportsDirectoryIsBlank() {
        ReportFileWriter writer = new ReportFileWriter(objectMapper, "");

        // Must not throw even though there's nowhere configured to write to.
        writer.write(sampleReport());
    }

    private ScanReport sampleReport() {
        Instant now = Instant.now();
        return new ScanReport("report-id", "http://localhost:8080", now, now, 42, 1, 1, null,
                List.of(), new ScanSummary(0, Map.of(Severity.INFO, 0),
                        Map.of(VulnerabilityType.SQL_INJECTION_ERROR_BASED, 0), Severity.INFO, 0),
                "narrativa di prova");
    }
}
