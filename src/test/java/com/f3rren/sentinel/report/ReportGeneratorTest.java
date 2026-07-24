package com.f3rren.sentinel.report;

import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ReportGeneratorTest {

    private final ReportGenerator reportGenerator = new ReportGenerator();

    @Test
    void summarizesNoFindingsAsInfoRiskWithHtmlCrawlNarrative() {
        Instant start = Instant.parse("2026-01-01T10:00:00Z");
        Instant end = Instant.parse("2026-01-01T10:00:00.500Z");

        ScanReport report = reportGenerator.buildReport(
                "scan-1", "http://localhost:8080", start, end, 3, null, List.of());

        assertThat(report.summary().totalFindings()).isEqualTo(0);
        assertThat(report.summary().overallRisk()).isEqualTo(Severity.INFO);
        assertThat(report.summary().countsBySeverity().values()).allMatch(count -> count == 0);
        assertThat(report.narrative())
                .contains("http://localhost:8080")
                .contains("500 ms")
                .contains("scansione della pagina HTML")
                .contains("3")
                .contains("Nessuna vulnerabilità rilevata.");
    }

    @Test
    void mentionsOpenApiSpecUrlInNarrativeWhenPresent() {
        Instant start = Instant.parse("2026-01-01T10:00:00Z");
        Instant end = Instant.parse("2026-01-01T10:00:08.100Z");

        ScanReport report = reportGenerator.buildReport(
                "scan-2", "http://api-gateway:8080", start, end, 46,
                "http://api-gateway:8080/v3/api-docs/swagger-config", List.of());

        assertThat(report.narrative())
                .contains("8,1 secondi")
                .contains("spec OpenAPI/Swagger")
                .contains("http://api-gateway:8080/v3/api-docs/swagger-config")
                .contains("46");
    }

    @Test
    void computesOverallRiskAsHighestSeverityAndListsBreakdownInNarrative() {
        Instant start = Instant.parse("2026-01-01T10:00:00Z");
        Instant end = Instant.parse("2026-01-01T10:00:01Z");
        List<Finding> findings = List.of(
                finding(VulnerabilityType.SQL_INJECTION_BOOLEAN_BASED, Severity.HIGH),
                finding(VulnerabilityType.SQL_INJECTION_ERROR_BASED, Severity.CRITICAL),
                finding(VulnerabilityType.SQL_INJECTION_ERROR_BASED, Severity.CRITICAL)
        );

        ScanReport report = reportGenerator.buildReport(
                "scan-3", "http://localhost:8080", start, end, 5, null, findings);

        assertThat(report.summary().totalFindings()).isEqualTo(3);
        assertThat(report.summary().overallRisk()).isEqualTo(Severity.CRITICAL);
        assertThat(report.summary().countsBySeverity().get(Severity.CRITICAL)).isEqualTo(2);
        assertThat(report.summary().countsBySeverity().get(Severity.HIGH)).isEqualTo(1);
        assertThat(report.narrative())
                .contains("Rilevate 3 vulnerabilità")
                .contains("rischio complessivo: CRITICAL")
                // CRITICAL must be listed before HIGH: most severe first.
                .containsPattern("2 CRITICAL.*1 HIGH");
    }

    private Finding finding(VulnerabilityType type, Severity severity) {
        return new Finding("id", type, severity, "http://localhost:8080/x", HttpMethod.GET.name(),
                "param", "payload", "description", "evidence", "recommendation");
    }
}
