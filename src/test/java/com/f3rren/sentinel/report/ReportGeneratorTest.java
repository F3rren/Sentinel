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
                "scan-1", "http://localhost:8080", start, end, 3, 3, null, List.of());

        assertThat(report.summary().totalFindings()).isEqualTo(0);
        assertThat(report.summary().overallRisk()).isEqualTo(Severity.INFO);
        assertThat(report.summary().countsBySeverity().values()).allMatch(count -> count == 0);
        assertThat(report.summary().countsByType().values()).allMatch(count -> count == 0);
        assertThat(report.summary().riskScore()).isZero();
        assertThat(report.narrative())
                .contains("http://localhost:8080")
                .contains("500 ms")
                .contains("scansione della pagina HTML")
                .contains("3")
                .contains("Nessuna vulnerabilità rilevata.")
                // all 3 discovered were also tested: no extra "tested" clause expected.
                .doesNotContain("Testati effettivamente");
    }

    @Test
    void mentionsTestedCountInNarrativeWhenLowerThanDiscovered() {
        Instant start = Instant.parse("2026-01-01T10:00:00Z");
        Instant end = Instant.parse("2026-01-01T10:00:00.500Z");

        ScanReport report = reportGenerator.buildReport(
                "scan-4", "http://api-gateway:8080", start, end, 46, 12, null, List.of());

        assertThat(report.endpointsDiscovered()).isEqualTo(46);
        assertThat(report.endpointsTested()).isEqualTo(12);
        assertThat(report.narrative())
                .contains("46")
                .contains("Testati effettivamente 12");
    }

    @Test
    void mentionsOpenApiSpecUrlInNarrativeWhenPresent() {
        Instant start = Instant.parse("2026-01-01T10:00:00Z");
        Instant end = Instant.parse("2026-01-01T10:00:08.100Z");

        ScanReport report = reportGenerator.buildReport(
                "scan-2", "http://api-gateway:8080", start, end, 46, 46,
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
                "scan-3", "http://localhost:8080", start, end, 5, 5, null, findings);

        assertThat(report.summary().totalFindings()).isEqualTo(3);
        assertThat(report.summary().overallRisk()).isEqualTo(Severity.CRITICAL);
        assertThat(report.summary().countsBySeverity().get(Severity.CRITICAL)).isEqualTo(2);
        assertThat(report.summary().countsBySeverity().get(Severity.HIGH)).isEqualTo(1);
        // 2 CRITICAL (weight 40 each) + 1 HIGH (weight 20) = 100.
        assertThat(report.summary().riskScore()).isEqualTo(100);
        assertThat(report.narrative())
                .contains("Rilevate 3 vulnerabilità")
                .contains("rischio complessivo: CRITICAL")
                .contains("punteggio di rischio: 100")
                // CRITICAL must be listed before HIGH: most severe first.
                .containsPattern("2 CRITICAL.*1 HIGH");
    }

    @Test
    void breaksDownFindingsByTypeAcrossDifferentVulnerabilityCategories() {
        Instant start = Instant.parse("2026-01-01T10:00:00Z");
        Instant end = Instant.parse("2026-01-01T10:00:01Z");
        List<Finding> findings = List.of(
                finding(VulnerabilityType.MISSING_AUTHENTICATION, Severity.HIGH),
                finding(VulnerabilityType.MISSING_AUTHENTICATION, Severity.HIGH),
                finding(VulnerabilityType.MISSING_AUTHENTICATION, Severity.MEDIUM),
                finding(VulnerabilityType.SQL_INJECTION_ERROR_BASED, Severity.CRITICAL)
        );

        ScanReport report = reportGenerator.buildReport(
                "scan-5", "http://localhost:8080", start, end, 4, 4, null, findings);

        assertThat(report.summary().countsByType().get(VulnerabilityType.MISSING_AUTHENTICATION)).isEqualTo(3);
        assertThat(report.summary().countsByType().get(VulnerabilityType.SQL_INJECTION_ERROR_BASED)).isEqualTo(1);
        assertThat(report.summary().countsByType().get(VulnerabilityType.SQL_INJECTION_BOOLEAN_BASED)).isEqualTo(0);
        assertThat(report.narrative())
                .contains("Per tipologia:")
                // most frequent type listed first.
                .containsPattern("3 MISSING_AUTHENTICATION.*1 SQL_INJECTION_ERROR_BASED");
    }

    private Finding finding(VulnerabilityType type, Severity severity) {
        return new Finding("id", type, severity, "http://localhost:8080/x", HttpMethod.GET.name(),
                "param", "payload", "description", "evidence", "recommendation");
    }
}
