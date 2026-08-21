package com.f3rren.sentinel.report;

import com.f3rren.sentinel.model.FindingGroup;
import com.f3rren.sentinel.model.FindingOccurrence;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SarifConverterTest {

    private final SarifConverter converter = new SarifConverter(new ObjectMapper(), "1.0.0-test");

    @Test
    void producesValidSarifSkeleton() {
        ObjectNode sarif = converter.toSarif(reportWith(List.of()));

        assertThat(sarif.get("version").asString()).isEqualTo("2.1.0");
        assertThat(sarif.get("$schema").asString()).contains("sarif-2.1.0");
        assertThat(sarif.get("runs").size()).isEqualTo(1);
        JsonNode driver = sarif.get("runs").get(0).get("tool").get("driver");
        assertThat(driver.get("name").asString()).isEqualTo("Sentinel");
        assertThat(driver.get("version").asString()).isEqualTo("1.0.0-test");
    }

    @Test
    void emitsOneRulePerTypeAndOneResultPerOccurrence() {
        FindingGroup idor = new FindingGroup("idor", VulnerabilityType.IDOR,
                "Ownership not enforced.", "Check ownership.",
                List.of(new FindingOccurrence("1", Severity.HIGH, "http://t/aquariums/99", "GET", "", "", "B read A's resource.")));
        FindingGroup rateLimit = new FindingGroup("rate-limit", VulnerabilityType.MISSING_RATE_LIMITING,
                "No throttling.", "Add rate limiting.",
                List.of(
                        new FindingOccurrence("2", Severity.LOW, "http://t/a", "GET", "", "", "no 429"),
                        new FindingOccurrence("3", Severity.LOW, "http://t/b", "GET", "", "", "no 429")));

        ObjectNode sarif = converter.toSarif(reportWith(List.of(idor, rateLimit)));
        JsonNode run = sarif.get("runs").get(0);

        // one rule per distinct type
        JsonNode rules = run.get("tool").get("driver").get("rules");
        assertThat(rules.size()).isEqualTo(2);
        assertThat(rules.get(0).get("id").asString()).isEqualTo("IDOR");
        assertThat(rules.get(0).get("properties").get("security-severity").asString()).isEqualTo("8.0");

        // one result per occurrence (1 + 2 = 3)
        JsonNode results = run.get("results");
        assertThat(results.size()).isEqualTo(3);
    }

    @Test
    void mapsSeverityToSarifLevelAndLocation() {
        FindingGroup idor = new FindingGroup("idor", VulnerabilityType.IDOR,
                "Ownership not enforced.", "Check ownership.",
                List.of(new FindingOccurrence("1", Severity.HIGH, "http://t/aquariums/99", "GET", "", "", "evidence text")));

        JsonNode result = converter.toSarif(reportWith(List.of(idor))).get("runs").get(0).get("results").get(0);

        assertThat(result.get("ruleId").asString()).isEqualTo("IDOR");
        assertThat(result.get("level").asString()).isEqualTo("error"); // HIGH -> error
        assertThat(result.get("message").get("text").asString()).contains("evidence text");
        assertThat(result.get("locations").get(0).get("physicalLocation").get("artifactLocation").get("uri").asString())
                .isEqualTo("http://t/aquariums/99");
        assertThat(result.get("properties").get("severity").asString()).isEqualTo("HIGH");
        assertThat(result.get("partialFingerprints").get("sentinel/v1").asString()).isNotBlank();
    }

    @Test
    void lowSeverityBecomesNoteAndMediumBecomesWarning() {
        FindingGroup lowGroup = new FindingGroup("rate-limit", VulnerabilityType.MISSING_RATE_LIMITING,
                "No throttling.", "Add rate limiting.",
                List.of(new FindingOccurrence("1", Severity.LOW, "http://t/a", "GET", "", "", "e")));
        FindingGroup mediumGroup = new FindingGroup("missing-authentication", VulnerabilityType.MISSING_AUTHENTICATION,
                "No auth.", "Require auth.",
                List.of(new FindingOccurrence("2", Severity.MEDIUM, "http://t/b", "GET", "", "", "e")));

        JsonNode results = converter.toSarif(reportWith(List.of(lowGroup, mediumGroup))).get("runs").get(0).get("results");

        assertThat(results.get(0).get("level").asString()).isEqualTo("note");     // LOW
        assertThat(results.get(1).get("level").asString()).isEqualTo("warning");  // MEDIUM
    }

    @Test
    void fallsBackToTargetUrlWhenAnOccurrenceHasNoEndpoint() {
        FindingGroup jwt = new FindingGroup("jwt-weak-secret", VulnerabilityType.WEAK_JWT_SECRET,
                "Weak signing secret.", "Rotate it.",
                List.of(new FindingOccurrence("1", Severity.CRITICAL, "", "", "", "", "cracked")));

        JsonNode result = converter.toSarif(reportWith(List.of(jwt))).get("runs").get(0).get("results").get(0);

        assertThat(result.get("locations").get(0).get("physicalLocation").get("artifactLocation").get("uri").asString())
                .isEqualTo("http://target.example");
        assertThat(result.get("level").asString()).isEqualTo("error"); // CRITICAL -> error
    }

    private ScanReport reportWith(List<FindingGroup> findings) {
        Instant now = Instant.now();
        ScanSummary summary = new ScanSummary(0, Map.of(), Map.of(), Severity.INFO, 0, false);
        return new ScanReport("id", "http://target.example", now, now, 0, 0, 0, null, findings, summary, "narrative");
    }
}
