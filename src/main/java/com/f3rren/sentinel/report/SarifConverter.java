package com.f3rren.sentinel.report;

import com.f3rren.sentinel.model.FindingGroup;
import com.f3rren.sentinel.model.FindingOccurrence;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Renders a {@link ScanReport} as SARIF 2.1.0 (Static Analysis Results Interchange Format), the
 * format GitHub code scanning ingests: uploaded to a repository, the findings show up in its
 * Security tab, bucketed by severity, and de-duplicated across runs via a stable fingerprint - so
 * Sentinel can act as a DAST step in a CI/CD pipeline rather than only emitting its own JSON.
 * <p>
 * Each distinct {@link VulnerabilityType} present becomes a SARIF <em>rule</em>; each individual
 * {@link FindingOccurrence} becomes a <em>result</em> pointing at the affected endpoint URL. GitHub
 * reads {@code security-severity} (a CVSS-shaped 0-10 number) from the rule to bucket it into
 * critical/high/medium/low; the per-result {@code level} carries the individual occurrence's
 * severity. A clean scan produces valid SARIF with an empty {@code results} array.
 */
@Component
public class SarifConverter {

    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    private static final String TOOL_NAME = "Sentinel";
    private static final String TOOL_URI = "https://github.com/f3rren/Sentinel";

    private final ObjectMapper objectMapper;
    private final String toolVersion;

    public SarifConverter(
            ObjectMapper objectMapper,
            @Value("${sentinel.version:dev}") String toolVersion) {
        this.objectMapper = objectMapper;
        this.toolVersion = toolVersion;
    }

    public ObjectNode toSarif(ScanReport report) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("$schema", SCHEMA);
        root.put("version", "2.1.0");

        ObjectNode run = objectMapper.createObjectNode();

        // One rule per distinct vulnerability type present, remembering the order so results can
        // reference it by index. A type's rule-level security-severity is set from the worst
        // severity seen among that type's occurrences (GitHub buckets the rule by this number).
        Map<VulnerabilityType, Integer> ruleIndexByType = new LinkedHashMap<>();
        Map<VulnerabilityType, Severity> worstSeverityByType = new LinkedHashMap<>();
        for (FindingGroup group : report.findings()) {
            worstSeverityByType.merge(group.type(), worstSeverity(group), SarifConverter::maxSeverity);
        }

        ArrayNode rules = objectMapper.createArrayNode();
        ArrayNode results = objectMapper.createArrayNode();

        for (FindingGroup group : report.findings()) {
            int ruleIndex = ruleIndexByType.computeIfAbsent(group.type(), type -> {
                rules.add(buildRule(group, worstSeverityByType.get(type)));
                return rules.size() - 1;
            });
            for (FindingOccurrence occurrence : group.occurrences()) {
                results.add(buildResult(report, group, occurrence, ruleIndex));
            }
        }

        ObjectNode driver = objectMapper.createObjectNode();
        driver.put("name", TOOL_NAME);
        driver.put("informationUri", TOOL_URI);
        driver.put("version", toolVersion);
        driver.set("rules", rules);

        ObjectNode tool = objectMapper.createObjectNode();
        tool.set("driver", driver);
        run.set("tool", tool);
        run.set("results", results);

        ArrayNode runs = objectMapper.createArrayNode();
        runs.add(run);
        root.set("runs", runs);
        return root;
    }

    private ObjectNode buildRule(FindingGroup group, Severity worstSeverity) {
        ObjectNode rule = objectMapper.createObjectNode();
        rule.put("id", group.type().name());
        rule.put("name", group.type().name());
        rule.set("shortDescription", text(group.description()));
        rule.set("fullDescription", text(group.recommendation()));

        ObjectNode properties = objectMapper.createObjectNode();
        properties.put("security-severity", securitySeverity(worstSeverity));
        ArrayNode tags = objectMapper.createArrayNode();
        tags.add("security");
        tags.add("external/cwe");
        properties.set("tags", tags);
        rule.set("properties", properties);
        return rule;
    }

    private ObjectNode buildResult(ScanReport report, FindingGroup group, FindingOccurrence occurrence, int ruleIndex) {
        ObjectNode result = objectMapper.createObjectNode();
        result.put("ruleId", group.type().name());
        result.put("ruleIndex", ruleIndex);
        result.put("level", sarifLevel(occurrence.severity()));

        String message = group.description();
        if (occurrence.evidence() != null && !occurrence.evidence().isBlank()) {
            message = message + " " + occurrence.evidence();
        }
        result.set("message", text(message));

        String uri = (occurrence.endpointUrl() == null || occurrence.endpointUrl().isBlank())
                ? report.targetUrl()
                : occurrence.endpointUrl();
        ObjectNode artifactLocation = objectMapper.createObjectNode();
        artifactLocation.put("uri", uri);
        ObjectNode physicalLocation = objectMapper.createObjectNode();
        physicalLocation.set("artifactLocation", artifactLocation);
        ObjectNode location = objectMapper.createObjectNode();
        location.set("physicalLocation", physicalLocation);
        ArrayNode locations = objectMapper.createArrayNode();
        locations.add(location);
        result.set("locations", locations);

        // A stable fingerprint so GitHub tracks the same issue across runs instead of re-alerting:
        // keyed on what identifies the finding (type + endpoint + parameter), not on volatile
        // fields like the generated payload value or the finding's random id.
        ObjectNode fingerprints = objectMapper.createObjectNode();
        fingerprints.put("sentinel/v1", fingerprint(group.type(), uri, occurrence.method(), occurrence.parameter()));
        result.set("partialFingerprints", fingerprints);

        ObjectNode properties = objectMapper.createObjectNode();
        properties.put("severity", occurrence.severity().name());
        properties.put("module", group.module());
        properties.put("method", nullToEmpty(occurrence.method()));
        properties.put("parameter", nullToEmpty(occurrence.parameter()));
        properties.put("security-severity", securitySeverity(occurrence.severity()));
        result.set("properties", properties);
        return result;
    }

    private ObjectNode text(String value) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("text", value == null ? "" : value);
        return node;
    }

    /** SARIF result levels: only error/warning/note exist, so severities collapse onto them. */
    private static String sarifLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    /**
     * GitHub buckets a finding into critical/high/medium/low from this CVSS-shaped 0-10 string
     * (>=9 critical, 7-8.9 high, 4-6.9 medium, <4 low), read from the rule's properties.
     */
    private static String securitySeverity(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "9.5";
            case HIGH -> "8.0";
            case MEDIUM -> "5.5";
            case LOW -> "3.0";
            case INFO -> "0.0";
        };
    }

    private static Severity worstSeverity(FindingGroup group) {
        Severity worst = Severity.INFO;
        for (FindingOccurrence occurrence : group.occurrences()) {
            worst = maxSeverity(worst, occurrence.severity());
        }
        return worst;
    }

    private static Severity maxSeverity(Severity a, Severity b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    private static String fingerprint(VulnerabilityType type, String uri, String method, String parameter) {
        String seed = type.name() + "|" + method + "|" + uri + "|" + nullToEmpty(parameter);
        return Integer.toHexString(seed.toLowerCase(Locale.ROOT).hashCode());
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
