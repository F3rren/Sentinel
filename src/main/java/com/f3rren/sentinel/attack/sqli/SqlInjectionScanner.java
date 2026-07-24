package com.f3rren.sentinel.attack.sqli;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Fuzzes each discovered parameter with classic SQL injection payloads and looks for two
 * independent signals: a leaked database error message (error-based) or a response that
 * flips shape between an always-true and an always-false boolean condition (boolean-based /
 * blind). Both checks are best-effort heuristics aimed at a low false-positive rate rather
 * than exhaustive coverage.
 * <p>
 * Disabled by setting {@code sentinel.scan.sql-injection.enabled=false} (env
 * {@code SENTINEL_SCAN_SQL_INJECTION_ENABLED=false}): the bean simply isn't created, so it
 * never joins the {@code List<AttackModule>} that {@code ScanService} runs against every
 * endpoint. Future modules (XSS, brute force, ...) follow the same
 * {@code sentinel.scan.<module>.enabled} convention.
 */
@Component
@ConditionalOnProperty(prefix = "sentinel.scan.sql-injection", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SqlInjectionScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(SqlInjectionScanner.class);

    private static final String RECOMMENDATION =
            "Utilizzare sempre query parametrizzate (prepared statement) o un ORM con binding "
            + "sicuro dei parametri, evitando la concatenazione di input utente nelle query SQL. "
            + "Validare e whitelistare l'input lato server, applicare il principio del privilegio "
            + "minimo all'utente del database ed evitare di esporre stack trace o messaggi di "
            + "errore del database in produzione.";

    private static final List<String> ERROR_BASED_PAYLOADS = List.of(
            "'",
            "\"",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "1' ORDER BY 100-- ",
            "' UNION SELECT NULL-- ",
            "\" OR \"1\"=\"1"
    );

    private static final String BOOLEAN_TRUE_PAYLOAD = "' OR '1'='1' -- ";
    private static final String BOOLEAN_FALSE_PAYLOAD = "' AND '1'='2' -- ";

    private final SentinelHttpClient httpClient;

    public SqlInjectionScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "sql-injection";
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        List<Finding> findings = new java.util.ArrayList<>();
        Map<String, String> baselineParams = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            baselineParams.put(param.name(), param.sampleValue());
        }

        HttpResponseData baseline;
        try {
            baseline = httpClient.exchange(endpoint.method(), endpoint.url(), baselineParams, endpoint.requestBodySample());
        } catch (Exception e) {
            log.warn("Baseline request failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return findings;
        }

        Optional<SqlErrorSignatures.MatchResult> baselineError = SqlErrorSignatures.find(baseline.bodyOrEmpty());

        for (EndpointParam param : endpoint.params()) {
            try {
                Optional<Finding> errorBased = checkErrorBased(endpoint, param, baselineParams, baselineError.isPresent());
                if (errorBased.isPresent()) {
                    findings.add(errorBased.get());
                    continue;
                }
                if (baseline.statusCode() == 200) {
                    checkBooleanBased(endpoint, param, baselineParams, baseline).ifPresent(findings::add);
                }
            } catch (Exception e) {
                log.warn("SQLi check failed for {} {} param={}: {}", endpoint.method(), endpoint.url(), param.name(), e.getMessage());
            }
        }
        return findings;
    }

    private Optional<Finding> checkErrorBased(Endpoint endpoint, EndpointParam param, Map<String, String> baselineParams, boolean baselineAlreadyErrors) throws Exception {
        if (baselineAlreadyErrors) {
            // The endpoint already leaks DB errors on benign input: signatures are not a reliable
            // signal here, skip to avoid false positives.
            return Optional.empty();
        }
        for (String payload : ERROR_BASED_PAYLOADS) {
            Map<String, String> params = new LinkedHashMap<>(baselineParams);
            params.put(param.name(), payload);
            HttpResponseData response = httpClient.exchange(endpoint.method(), endpoint.url(), params);
            Optional<SqlErrorSignatures.MatchResult> match = SqlErrorSignatures.find(response.bodyOrEmpty());
            if (match.isPresent()) {
                return Optional.of(new Finding(
                        UUID.randomUUID().toString(),
                        VulnerabilityType.SQL_INJECTION_ERROR_BASED,
                        Severity.CRITICAL,
                        endpoint.url(),
                        endpoint.method().name(),
                        param.name(),
                        payload,
                        "Il parametro '" + param.name() + "' riflette un messaggio di errore del "
                                + "database (" + match.get().database() + ") in risposta a un payload SQL injection.",
                        match.get().snippet(),
                        RECOMMENDATION
                ));
            }
        }
        return Optional.empty();
    }

    private Optional<Finding> checkBooleanBased(Endpoint endpoint, EndpointParam param, Map<String, String> baselineParams, HttpResponseData baseline) throws Exception {
        Map<String, String> trueParams = new LinkedHashMap<>(baselineParams);
        trueParams.put(param.name(), BOOLEAN_TRUE_PAYLOAD);
        Map<String, String> falseParams = new LinkedHashMap<>(baselineParams);
        falseParams.put(param.name(), BOOLEAN_FALSE_PAYLOAD);

        HttpResponseData trueResponse = httpClient.exchange(endpoint.method(), endpoint.url(), trueParams);
        HttpResponseData falseResponse = httpClient.exchange(endpoint.method(), endpoint.url(), falseParams);

        if (trueResponse.statusCode() == 429 || falseResponse.statusCode() == 429) {
            // A 429 means the target's rate limiter reacted to Sentinel's own request volume
            // (this same param already took a baseline + up to 8 error-based payloads before
            // either of these two), not to the injected condition's truth value. Comparing
            // against a throttled response would read pure throttling as a signal.
            return Optional.empty();
        }

        int baseLen = baseline.bodyOrEmpty().length();
        int trueLen = trueResponse.bodyOrEmpty().length();
        int falseLen = falseResponse.bodyOrEmpty().length();
        int threshold = Math.max(40, (int) (baseLen * 0.15));

        boolean statusDiffers = trueResponse.statusCode() == 200 && trueResponse.statusCode() != falseResponse.statusCode();
        boolean trueMatchesBaselineShape = Math.abs(trueLen - baseLen) < threshold;
        boolean bodyDiffers = Math.abs(trueLen - falseLen) > threshold;

        if (statusDiffers || (trueMatchesBaselineShape && bodyDiffers)) {
            String evidence = String.format(
                    "Lunghezza risposta - baseline: %d, condizione vera (%s): %d, condizione falsa (%s): %d, status vero/falso: %d/%d",
                    baseLen, BOOLEAN_TRUE_PAYLOAD, trueLen, BOOLEAN_FALSE_PAYLOAD, falseLen,
                    trueResponse.statusCode(), falseResponse.statusCode());
            return Optional.of(new Finding(
                    UUID.randomUUID().toString(),
                    VulnerabilityType.SQL_INJECTION_BOOLEAN_BASED,
                    Severity.HIGH,
                    endpoint.url(),
                    endpoint.method().name(),
                    param.name(),
                    BOOLEAN_TRUE_PAYLOAD,
                    "Il parametro '" + param.name() + "' produce risposte diverse tra una condizione "
                            + "booleana sempre vera e sempre falsa iniettata: possibile SQL injection "
                            + "blind/boolean-based.",
                    evidence,
                    RECOMMENDATION
            ));
        }
        return Optional.empty();
    }
}
