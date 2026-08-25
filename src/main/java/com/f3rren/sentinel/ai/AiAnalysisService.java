package com.f3rren.sentinel.ai;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.TextBlock;
import com.f3rren.sentinel.model.FindingGroup;
import com.f3rren.sentinel.model.FindingOccurrence;
import com.f3rren.sentinel.model.ScanReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Optional, opt-in end-of-scan analysis powered by Claude (official Anthropic SDK).
 * <p>
 * This layer is deliberately <strong>isolated from the deterministic detection engine</strong>:
 * it never produces, alters, or suppresses a finding. It runs exactly once, after a scan is
 * complete, on the already-built and already-redacted report, and returns a natural-language
 * commentary that gets attached as {@link ScanReport#aiAnalysis()}. Everything about it is
 * best-effort - disabled by default, and any failure (no API key, network error, rate limit,
 * malformed response) is swallowed and logged, so enabling AI analysis can never break or fail a
 * scan.
 * <p>
 * Only the redacted report is sent to the model: findings already carry field names and paths,
 * never the underlying secret values, so no sensitive data leaves the process here that isn't
 * already in the report the user is holding.
 */
@Component
public class AiAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(AiAnalysisService.class);

    private static final String SYSTEM_PROMPT = """
            You are a senior application-security analyst reviewing the output of Sentinel, an
            automated black-box API security scanner. You are given the scanner's finished report
            for a single authorized scan. The findings were produced by deterministic detection
            modules; do not invent, contradict, or re-classify them.

            Write a concise executive analysis for the engineer who ran the scan:
            1. A one-paragraph overall risk assessment.
            2. The findings that most warrant immediate attention and why, in priority order.
            3. Practical, specific remediation guidance grouped by theme where findings overlap.
            4. Any caveats a reader should keep in mind (e.g. a partial scan flagged as
               rate-limited, or the absence of findings not proving the target is secure).

            Be direct and technical. Do not pad. If the report contains no findings, say so plainly
            and note what that does and does not guarantee. Never fabricate findings, endpoints, or
            severities that are not present in the report.""";

    private final boolean enabled;
    private final String model;
    private final long maxTokens;

    public AiAnalysisService(
            @Value("${sentinel.ai.enabled:false}") boolean enabled,
            @Value("${sentinel.ai.model:claude-opus-5}") String model,
            @Value("${sentinel.ai.max-tokens:4000}") long maxTokens
    ) {
        this.enabled = enabled;
        this.model = model;
        this.maxTokens = maxTokens;
    }

    /**
     * Returns Claude's analysis of the report, or {@link Optional#empty()} when AI analysis is
     * disabled or anything at all goes wrong. Never throws - the caller can safely attach the
     * result (or nothing) without guarding the call.
     */
    public Optional<String> analyze(ScanReport report) {
        if (!enabled) {
            return Optional.empty();
        }
        try {
            String analysis = callClaude(SYSTEM_PROMPT, buildUserPrompt(report));
            if (analysis == null || analysis.isBlank()) {
                log.warn("AI analysis returned an empty response for scan {}", report.id());
                return Optional.empty();
            }
            return Optional.of(analysis.trim());
        } catch (Exception e) {
            // Best-effort by design: an AI failure must never fail the scan it is commenting on.
            log.warn("AI analysis failed for scan {} - continuing without it: {}", report.id(), e.toString());
            return Optional.empty();
        }
    }

    /**
     * Issues the single Claude call. Isolated into a protected method so tests can exercise
     * {@link #analyze(ScanReport)} end to end by overriding this, without a live API key or
     * network access. Builds the client here (rather than as a field) so the process starts fine
     * with AI disabled and no ANTHROPIC_API_KEY set - the key is only ever required at the moment
     * an enabled analysis actually runs.
     */
    protected String callClaude(String system, String user) {
        AnthropicClient client = AnthropicOkHttpClient.fromEnv();
        MessageCreateParams params = MessageCreateParams.builder()
                .model(model)
                .maxTokens(maxTokens)
                .system(system)
                .addUserMessage(user)
                .build();
        Message response = client.messages().create(params);
        return response.content().stream()
                .flatMap(block -> block.text().stream())
                .map(TextBlock::text)
                .collect(Collectors.joining("\n"));
    }

    /**
     * Renders the finished report into a compact, plain-text prompt. Uses only what is already in
     * the redacted report - target, counts, and each finding's type/severity/location/evidence -
     * so nothing sensitive beyond what the report itself already contains is ever sent.
     */
    static String buildUserPrompt(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scan target: ").append(report.targetUrl()).append('\n');
        sb.append("Endpoints discovered: ").append(report.endpointsDiscovered())
                .append(", tested: ").append(report.endpointsTested()).append('\n');
        if (report.openApiSpecUrl() != null) {
            sb.append("OpenAPI spec: ").append(report.openApiSpecUrl()).append('\n');
        }
        if (report.summary() != null) {
            sb.append("Overall risk: ").append(report.summary().overallRisk())
                    .append(", risk score: ").append(report.summary().riskScore())
                    .append(", total findings: ").append(report.summary().totalFindings()).append('\n');
            if (report.summary().possiblyRateLimited()) {
                sb.append("NOTE: the scan was likely throttled by the target - results are partial.\n");
            }
        }
        sb.append("\nScanner narrative:\n").append(report.narrative()).append('\n');

        if (report.findings() == null || report.findings().isEmpty()) {
            sb.append("\nNo findings were reported.\n");
        } else {
            sb.append("\nFindings (grouped by type):\n");
            int i = 1;
            for (FindingGroup group : report.findings()) {
                sb.append(i++).append(". [").append(group.type()).append("] ")
                        .append(group.description()).append('\n');
                sb.append("   Recommendation: ").append(group.recommendation()).append('\n');
                sb.append("   Affected occurrences: ").append(group.occurrences().size()).append('\n');
                for (FindingOccurrence occ : group.occurrences()) {
                    sb.append("     - ").append(occ.severity()).append(' ')
                            .append(occ.method()).append(' ').append(occ.endpointUrl());
                    if (occ.parameter() != null && !occ.parameter().isBlank()) {
                        sb.append(" (param: ").append(occ.parameter()).append(')');
                    }
                    if (occ.evidence() != null && !occ.evidence().isBlank()) {
                        sb.append(" - evidence: ").append(occ.evidence());
                    }
                    sb.append('\n');
                }
            }
        }
        return sb.toString();
    }
}
