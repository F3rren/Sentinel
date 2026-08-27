package com.f3rren.sentinel.ai;

import com.f3rren.sentinel.model.FindingGroup;
import com.f3rren.sentinel.model.FindingOccurrence;
import com.f3rren.sentinel.model.ScanReport;
import com.f3rren.sentinel.model.ScanSummary;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AiAnalysisServiceTest {

    @Test
    void returnsEmptyWhenDisabledWithoutEverCallingClaude() {
        AtomicReference<Boolean> called = new AtomicReference<>(false);
        AiAnalysisService service = new AiAnalysisService(false, "claude-opus-5", 4000) {
            @Override
            protected String callClaude(String system, String user) {
                called.set(true);
                return "should not happen";
            }
        };

        Optional<String> result = service.analyze(reportWithOneFinding());

        assertThat(result).isEmpty();
        assertThat(called.get()).isFalse();
    }

    @Test
    void returnsClaudeTextWhenEnabled() {
        AiAnalysisService service = new AiAnalysisService(true, "claude-opus-5", 4000) {
            @Override
            protected String callClaude(String system, String user) {
                return "  Overall risk is HIGH. Fix the IDOR first.  ";
            }
        };

        Optional<String> result = service.analyze(reportWithOneFinding());

        assertThat(result).contains("Overall risk is HIGH. Fix the IDOR first.");
    }

    @Test
    void swallowsFailuresAndReturnsEmptySoAScanNeverBreaks() {
        AiAnalysisService service = new AiAnalysisService(true, "claude-opus-5", 4000) {
            @Override
            protected String callClaude(String system, String user) {
                throw new RuntimeException("no ANTHROPIC_API_KEY / network down");
            }
        };

        Optional<String> result = service.analyze(reportWithOneFinding());

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyWhenClaudeGivesBackBlankText() {
        AiAnalysisService service = new AiAnalysisService(true, "claude-opus-5", 4000) {
            @Override
            protected String callClaude(String system, String user) {
                return "   ";
            }
        };

        assertThat(service.analyze(reportWithOneFinding())).isEmpty();
    }

    @Test
    void passesTheReportContentIntoThePrompt() {
        AtomicReference<String> capturedPrompt = new AtomicReference<>();
        AiAnalysisService service = new AiAnalysisService(true, "claude-opus-5", 4000) {
            @Override
            protected String callClaude(String system, String user) {
                capturedPrompt.set(user);
                return "analysis";
            }
        };

        service.analyze(reportWithOneFinding());

        String prompt = capturedPrompt.get();
        assertThat(prompt).contains("http://target.example");
        assertThat(prompt).contains("IDOR");
        assertThat(prompt).contains("/aquariums/99");
    }

    @Test
    void buildUserPromptStatesWhenThereAreNoFindings() {
        String prompt = AiAnalysisService.buildUserPrompt(reportWith(List.of()));

        assertThat(prompt).contains("No findings were reported.");
        assertThat(prompt).contains("http://target.example");
    }

    private ScanReport reportWithOneFinding() {
        FindingGroup idor = new FindingGroup("idor", VulnerabilityType.IDOR,
                "Ownership not enforced.", "Check ownership.",
                List.of(new FindingOccurrence("1", Severity.HIGH, "http://target.example/aquariums/99",
                        "GET", "", "", "B read A's resource.")));
        return reportWith(List.of(idor));
    }

    private ScanReport reportWith(List<FindingGroup> findings) {
        Instant now = Instant.now();
        int total = findings.stream().mapToInt(g -> g.occurrences().size()).sum();
        ScanSummary summary = new ScanSummary(total, Map.of(), Map.of(),
                total > 0 ? Severity.HIGH : Severity.INFO, total > 0 ? 20 : 0, false);
        return new ScanReport("id", "http://target.example", now, now, 0, 3, 3, null,
                findings, summary, "narrative text");
    }
}
