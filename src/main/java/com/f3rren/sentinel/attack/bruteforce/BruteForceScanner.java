package com.f3rren.sentinel.attack.bruteforce;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.discovery.SampleValues;
import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.EndpointParam;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Tries a short list of common/default credential pairs against endpoints that look like a
 * login: a {@code POST} whose request body (or, for HTML-form-discovered endpoints, whose
 * query/form parameters) has both a password-shaped and a username/email-shaped field. Two
 * independent, hedged signals come out of this:
 * <p>
 * - {@link VulnerabilityType#WEAK_CREDENTIALS} - one of the tried pairs was accepted, i.e. the
 *   endpoint let Sentinel log in with a guessable default password.
 * - {@link VulnerabilityType#MISSING_BRUTE_FORCE_PROTECTION} - none of the attempts ever got
 *   throttled (429) or locked out (423), which means nothing observed here would stop a real
 *   attacker from trying many more combinations. This is reported cautiously: a small, fixed
 *   attempt budget not tripping a lockout doesn't prove one doesn't exist at a higher threshold.
 * <p>
 * Deliberately conservative: a short fixed wordlist and a small attempt cap
 * ({@code sentinel.scan.brute-force.max-attempts}), rather than an exhaustive credential list,
 * to keep a single scan fast and to avoid hammering a real login endpoint (which may itself be
 * rate-limited, or could lock out a real account if a valid username were ever guessed).
 */
@Component
@ConditionalOnProperty(prefix = "sentinel.scan.brute-force", name = "enabled", havingValue = "true", matchIfMissing = true)
public class BruteForceScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(BruteForceScanner.class);

    private static final Pattern PASSWORD_KEY = Pattern.compile("pass(word)?|passwd|pwd", Pattern.CASE_INSENSITIVE);
    private static final Pattern USERNAME_KEY = Pattern.compile("user(name)?|e-?mail|login", Pattern.CASE_INSENSITIVE);
    private static final Pattern TOKEN_KEY = Pattern.compile("token|jwt|session", Pattern.CASE_INSENSITIVE);

    private static final List<Credential> COMMON_CREDENTIALS = List.of(
            new Credential("admin", "admin"),
            new Credential("admin", "password"),
            new Credential("admin", "admin123"),
            new Credential("admin", "123456"),
            new Credential("root", "root"),
            new Credential("administrator", "password"),
            new Credential("test", "test"),
            new Credential("user", "password")
    );

    private static final String WEAK_CREDENTIALS_RECOMMENDATION =
            "Non consentire credenziali di default o comuni per nessun account, applicativo o "
            + "amministrativo. Imporre una policy di password robuste, obbligare il cambio "
            + "password al primo accesso per account pre-creati e valutare l'autenticazione a "
            + "più fattori per gli account con privilegi elevati.";

    private static final String MISSING_PROTECTION_RECOMMENDATION =
            "Implementare rate-limiting o account lockout sugli endpoint di autenticazione (es. "
            + "blocco temporaneo dopo N tentativi falliti consecutivi, backoff progressivo o "
            + "CAPTCHA), per rendere impraticabile un attacco a forza bruta su larga scala.";

    private record Credential(String username, String password) {
    }

    @FunctionalInterface
    private interface CredentialAttempt {
        HttpResponseData send(String username, String password) throws Exception;
    }

    private final SentinelHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final int maxAttempts;

    public BruteForceScanner(SentinelHttpClient httpClient,
            @Value("${sentinel.scan.brute-force.max-attempts:8}") int maxAttempts) {
        this.httpClient = httpClient;
        this.maxAttempts = maxAttempts;
    }

    @Override
    public String name() {
        return "brute-force";
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        if (!HttpMethod.POST.equals(endpoint.method())) {
            return List.of();
        }

        if (endpoint.requestBodySample() != null) {
            JsonNode parsed = tryParse(endpoint.requestBodySample());
            if (parsed != null && parsed.isObject()) {
                ObjectNode template = (ObjectNode) parsed;
                List<String> passwordKeys = matchingKeys(template, PASSWORD_KEY);
                List<String> usernameKeys = matchingKeys(template, USERNAME_KEY);
                if (!passwordKeys.isEmpty() && !usernameKeys.isEmpty()) {
                    return runAttempts(endpoint, (username, password) -> {
                        ObjectNode body = template.deepCopy();
                        for (String key : passwordKeys) {
                            body.put(key, password);
                        }
                        for (String key : usernameKeys) {
                            body.put(key, username);
                        }
                        return httpClient.exchange(endpoint.method(), endpoint.url(), Map.of(), body.toString());
                    });
                }
            }
        }

        List<String> paramPasswordNames = endpoint.params().stream()
                .map(EndpointParam::name).filter(name -> PASSWORD_KEY.matcher(name).find()).toList();
        List<String> paramUsernameNames = endpoint.params().stream()
                .map(EndpointParam::name).filter(name -> USERNAME_KEY.matcher(name).find()).toList();
        if (paramPasswordNames.isEmpty() || paramUsernameNames.isEmpty()) {
            return List.of();
        }

        Map<String, String> baseParams = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            baseParams.put(param.name(), param.sampleValue());
        }
        return runAttempts(endpoint, (username, password) -> {
            Map<String, String> params = new LinkedHashMap<>(baseParams);
            for (String key : paramPasswordNames) {
                params.put(key, password);
            }
            for (String key : paramUsernameNames) {
                params.put(key, username);
            }
            return httpClient.exchange(endpoint.method(), endpoint.url(), params);
        });
    }

    private List<Finding> runAttempts(Endpoint endpoint, CredentialAttempt attempt) {
        HttpResponseData baseline;
        try {
            baseline = attempt.send("sentinel-" + UUID.randomUUID(), SampleValues.randomToken());
        } catch (Exception e) {
            log.warn("Brute-force baseline request failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();
        boolean everBlocked = false;
        int attempts = Math.min(maxAttempts, COMMON_CREDENTIALS.size());

        for (int i = 0; i < attempts; i++) {
            Credential credential = COMMON_CREDENTIALS.get(i);
            HttpResponseData response;
            try {
                response = attempt.send(credential.username(), credential.password());
            } catch (Exception e) {
                log.warn("Brute-force attempt failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
                continue;
            }

            if (response.statusCode() == 429 || response.statusCode() == 423) {
                everBlocked = true;
                continue;
            }

            if (isSuccessResponse(response, baseline)) {
                findings.add(weakCredentialsFinding(endpoint, credential, response));
                // Stop as soon as unauthorized access is proven: no reason to keep hammering a
                // real login endpoint once the point is made.
                return findings;
            }
        }

        if (!everBlocked) {
            findings.add(missingProtectionFinding(endpoint, attempts));
        }
        return findings;
    }

    private boolean isSuccessResponse(HttpResponseData response, HttpResponseData baseline) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return false;
        }
        if (baseline.statusCode() < 200 || baseline.statusCode() >= 300) {
            // The baseline used a definitely-wrong password and was correctly rejected: a 2xx
            // here, and only here, is a real signal.
            return true;
        }
        // The endpoint returns 2xx even for the wrong baseline credentials, so status alone
        // can't distinguish success - fall back to a token/session-shaped field in the body.
        return TOKEN_KEY.matcher(response.bodyOrEmpty()).find();
    }

    private List<String> matchingKeys(ObjectNode node, Pattern pattern) {
        List<String> keys = new ArrayList<>();
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            if (pattern.matcher(entry.getKey()).find()) {
                keys.add(entry.getKey());
            }
        }
        return keys;
    }

    private JsonNode tryParse(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            return null;
        }
    }

    private Finding weakCredentialsFinding(Endpoint endpoint, Credential credential, HttpResponseData response) {
        return new Finding(
                UUID.randomUUID().toString(),
                VulnerabilityType.WEAK_CREDENTIALS,
                Severity.CRITICAL,
                endpoint.url(),
                endpoint.method().name(),
                "",
                credential.username() + " / " + credential.password(),
                "L'endpoint ha accettato una combinazione di credenziali comuni/deboli come valida.",
                "Status " + response.statusCode() + " su " + endpoint.method() + " " + endpoint.url()
                        + " con le credenziali '" + credential.username() + "' / '" + credential.password() + "'.",
                WEAK_CREDENTIALS_RECOMMENDATION
        );
    }

    private Finding missingProtectionFinding(Endpoint endpoint, int attemptsMade) {
        return new Finding(
                UUID.randomUUID().toString(),
                VulnerabilityType.MISSING_BRUTE_FORCE_PROTECTION,
                Severity.LOW,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "L'endpoint non ha mai bloccato o rallentato Sentinel dopo " + attemptsMade
                        + " tentativi di login con credenziali diverse.",
                attemptsMade + " tentativi consecutivi senza mai ricevere uno status 429 (Too Many "
                        + "Requests) o 423 (Locked). Un numero di tentativi più alto potrebbe comunque "
                        + "attivare una protezione non ancora raggiunta da questo campione.",
                MISSING_PROTECTION_RECOMMENDATION
        );
    }
}
