package com.f3rren.sentinel.attack.sensitivefile;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Probes a small, fixed set of paths that have no business being reachable on a deployed web app -
 * a source-control directory, an environment file, a private key, a database or config backup -
 * host-level like {@link com.f3rren.sentinel.attack.actuator.ActuatorExposureScanner}: it only
 * needs to run once per scan (against the origin of whichever endpoint it sees first), not once
 * per endpoint, since exposure here is a deployment property, not something tied to any specific
 * discovered route.
 * <p>
 * Detection is a plain GET per candidate path, gated on two independent signals: a 2xx status
 * <em>and</em> the response body matching that file's own expected format (a git ref line, a
 * {@code [core]} section, a PEM private-key marker, ...). Status alone would false-positive on a
 * target that answers every unknown path with 200 (e.g. an SPA catch-all serving
 * {@code index.html}); the content check is what actually confirms the file is real rather than a
 * generic fallback response. Response bodies are never included in a finding's evidence - only the
 * probed path and its outcome - for the same reason {@code DataExposureScanner} never echoes the
 * value it found: the report itself must not become a copy of whatever secret it just uncovered.
 */
@Component
@Order(7)
@ConditionalOnProperty(prefix = "sentinel.scan.sensitive-file-exposure", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SensitiveFileExposureScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(SensitiveFileExposureScanner.class);

    private static final Pattern DOTENV_LINE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*\\s*=");

    private record Candidate(String path, Severity severity, Predicate<String> looksGenuine) {
    }

    private static final List<Candidate> CANDIDATES = List.of(
            // A checked-out .git directory lets an attacker reconstruct the entire source
            // history, including anything ever committed by mistake - CRITICAL.
            new Candidate(".git/HEAD", Severity.CRITICAL, body -> body.strip().startsWith("ref: refs/")),
            new Candidate(".git/config", Severity.CRITICAL, body -> body.contains("[core]")),
            // Environment files and private keys are direct credential/secret material - CRITICAL.
            new Candidate(".env", Severity.CRITICAL, SensitiveFileExposureScanner::looksLikeDotenv),
            new Candidate(".env.local", Severity.CRITICAL, SensitiveFileExposureScanner::looksLikeDotenv),
            new Candidate("id_rsa", Severity.CRITICAL, body -> body.contains("PRIVATE KEY-----")),
            // Infrastructure/config backups: real impact, but need the reader to go find the
            // credential inside them rather than handing one over directly - HIGH.
            new Candidate("docker-compose.yml", Severity.HIGH, body -> body.contains("services:")),
            new Candidate("backup.sql", Severity.HIGH, SensitiveFileExposureScanner::looksLikeSqlDump),
            // Config disclosure, not necessarily a secret by itself - MEDIUM.
            new Candidate("web.config", Severity.MEDIUM, body -> body.contains("<configuration"))
    );

    private static final String RECOMMENDATION =
            "Never let source control directories (.git), environment files, private keys, or "
            + "database/config backups end up in a web-reachable path. Exclude them at the web "
            + "server or static-resource layer, and audit build/deployment artifacts to make sure "
            + "they are never copied into the served directory in the first place.";

    private final SentinelHttpClient httpClient;

    private boolean checked;

    public SensitiveFileExposureScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "sensitive-file-exposure";
    }

    @Override
    public void beginScan(ScanContext context) {
        checked = false;
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        if (checked) {
            return List.of();
        }
        checked = true;

        String origin = originOf(endpoint.url());
        if (origin == null) {
            return List.of();
        }

        return CANDIDATES.stream()
                .map(candidate -> probe(origin, candidate))
                .filter(Objects::nonNull)
                .toList();
    }

    private Finding probe(String origin, Candidate candidate) {
        String url = origin + "/" + candidate.path();
        HttpResponseData response;
        try {
            response = httpClient.get(url);
        } catch (Exception e) {
            log.debug("Sensitive-file probe failed for {}: {}", url, e.getMessage());
            return null;
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return null;
        }
        if (!candidate.looksGenuine().test(response.bodyOrEmpty())) {
            return null;
        }
        return buildFinding(url, candidate);
    }

    private static boolean looksLikeDotenv(String body) {
        String firstMeaningfulLine = body.strip().lines()
                .map(String::strip)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .findFirst()
                .orElse("");
        return DOTENV_LINE.matcher(firstMeaningfulLine).find();
    }

    private static boolean looksLikeSqlDump(String body) {
        String upper = body.toUpperCase(Locale.ROOT);
        return upper.contains("CREATE TABLE") || upper.contains("INSERT INTO")
                || upper.contains("MYSQL DUMP") || upper.contains("POSTGRESQL DATABASE DUMP");
    }

    private static String originOf(String url) {
        try {
            URI uri = URI.create(url);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            String portSuffix = uri.getPort() == -1 ? "" : ":" + uri.getPort();
            return uri.getScheme() + "://" + uri.getHost() + portSuffix;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Finding buildFinding(String url, Candidate candidate) {
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.EXPOSED_SENSITIVE_FILE,
                candidate.severity(),
                url,
                "GET",
                candidate.path(),
                "",
                "A file that should never be web-reachable ('" + candidate.path() + "') is publicly "
                        + "exposed, and its content matches that file's expected format.",
                "GET " + url + " returned a successful response whose content matches the expected "
                        + "format of '" + candidate.path() + "' - the response body itself is not "
                        + "included in this report.",
                RECOMMENDATION
        );
    }
}
