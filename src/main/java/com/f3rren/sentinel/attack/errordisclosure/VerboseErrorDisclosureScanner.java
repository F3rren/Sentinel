package com.f3rren.sentinel.attack.errordisclosure;

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
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Fuzzes each discovered parameter, and (when present) every scalar field of a POST/PUT/PATCH
 * endpoint's own generated JSON body, with a single absurdly large number - a syntactically valid
 * value everywhere it's dropped in, but a classic trigger for the runtime exceptions (overflow,
 * downstream {@code parseLong}/{@code parseInt} on a value that was actually meant to be an
 * opaque string, an ID used as an array index or allocation size, ...) that a naive error handler
 * lets escape into the response instead of the generic "something went wrong" message a well-behaved
 * one returns. This is deliberately not about tripping a parser (that's a much narrower, much more
 * commonly already-handled failure mode, see {@code HttpMessageNotReadableException} et al.) - it's
 * about reaching past request parsing into actual business logic and seeing what leaks when that
 * logic breaks.
 * <p>
 * The response body (of every status code, not just 5xx - a leak could in principle ride along
 * with any response) is checked against a small, fixed set of unambiguous stack-trace/exception
 * signatures: a Java stack-frame line, a chained-exception {@code Caused by:} marker, a Python
 * traceback header, or a fully-qualified {@code Throwable.toString()}-shaped exception name. Only
 * which signature matched is reported - the matched text itself never appears in a finding's
 * evidence, since it may itself contain file paths, internal class names, or other detail that
 * shouldn't be duplicated into a second artifact.
 */
@Component
@Order(6)
@ConditionalOnProperty(prefix = "sentinel.scan.verbose-error-disclosure", name = "enabled", havingValue = "true", matchIfMissing = true)
public class VerboseErrorDisclosureScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(VerboseErrorDisclosureScanner.class);

    // Overflows any sane int/long parser, and is absurd wherever it lands - an ID, a quantity, a
    // free-text field suddenly holding forty digits - without breaking JSON syntax regardless of
    // which type it replaces.
    private static final String CHAOS_VALUE = "99999999999999999999999999999999999999";
    private static final BigInteger CHAOS_VALUE_AS_NUMBER = new BigInteger(CHAOS_VALUE);

    private record Signature(Pattern pattern, Severity severity, String label) {
    }

    private static final List<Signature> SIGNATURES = List.of(
            new Signature(Pattern.compile("\\bat\\s+[\\w$]+(?:\\.[\\w$]+)+\\([\\w.]*(?::\\d+)?\\)"),
                    Severity.HIGH, "a Java stack-trace frame"),
            new Signature(Pattern.compile("Caused by:"), Severity.HIGH, "a chained-exception 'Caused by:' marker"),
            new Signature(Pattern.compile("Traceback \\(most recent call last\\):"), Severity.HIGH, "a Python traceback header"),
            new Signature(Pattern.compile("(?:[a-z][a-zA-Z0-9]*\\.)+[A-Z][\\w$]*(?:Exception|Error):"),
                    Severity.MEDIUM, "a fully-qualified exception class name")
    );

    private static final String RECOMMENDATION =
            "Catch every exception a request handler can throw with a single top-level handler that "
            + "always returns a generic, fixed error message to the client - log the real exception "
            + "(with its stack trace) server-side only. Never let a framework's default error page or "
            + "an uncaught exception's own toString() reach the response body.";

    private final SentinelHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public VerboseErrorDisclosureScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "verbose-error-disclosure";
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        List<Finding> findings = new ArrayList<>();
        Map<String, String> baselineParams = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            baselineParams.put(param.name(), param.sampleValue());
        }

        for (EndpointParam param : endpoint.params()) {
            try {
                checkParam(endpoint, param, baselineParams).ifPresent(findings::add);
            } catch (Exception e) {
                log.warn("Verbose-error check failed for {} {} param={}: {}", endpoint.method(), endpoint.url(), param.name(), e.getMessage());
            }
        }

        if (endpoint.requestBodySample() != null) {
            try {
                checkBody(endpoint, baselineParams).ifPresent(findings::add);
            } catch (Exception e) {
                log.warn("Verbose-error body check failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            }
        }

        return findings;
    }

    private Optional<Finding> checkParam(Endpoint endpoint, EndpointParam param, Map<String, String> baselineParams) throws Exception {
        Map<String, String> params = new LinkedHashMap<>(baselineParams);
        params.put(param.name(), CHAOS_VALUE);
        HttpResponseData response = httpClient.exchange(endpoint.method(), endpoint.url(), params, endpoint.requestBodySample());
        if (isThrottled(response)) {
            return Optional.empty();
        }
        return matchSignature(response.bodyOrEmpty())
                .map(signature -> buildFinding(endpoint, param.name(), CHAOS_VALUE, signature));
    }

    private Optional<Finding> checkBody(Endpoint endpoint, Map<String, String> baselineParams) throws Exception {
        JsonNode baseBody;
        try {
            baseBody = objectMapper.readTree(endpoint.requestBodySample());
        } catch (Exception e) {
            return Optional.empty();
        }
        if (!baseBody.isObject()) {
            return Optional.empty();
        }

        ObjectNode chaosBody = ((ObjectNode) baseBody).deepCopy();
        replaceScalarsWithChaos(chaosBody);

        HttpResponseData response = httpClient.exchange(endpoint.method(), endpoint.url(), baselineParams, chaosBody.toString());
        if (isThrottled(response)) {
            return Optional.empty();
        }
        return matchSignature(response.bodyOrEmpty())
                .map(signature -> buildFinding(endpoint, "(request body)", CHAOS_VALUE, signature));
    }

    /**
     * Replaces every string/number leaf with {@link #CHAOS_VALUE} (as a JSON number where the
     * original was one, as a JSON string otherwise) - booleans and nulls are left alone, since
     * there's no meaningful "chaos" substitute for either that stays syntactically sensible.
     */
    private void replaceScalarsWithChaos(JsonNode node) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            for (String field : List.copyOf(object.propertyNames())) {
                JsonNode value = object.get(field);
                if (value.isTextual()) {
                    object.put(field, CHAOS_VALUE);
                } else if (value.isNumber()) {
                    object.put(field, CHAOS_VALUE_AS_NUMBER);
                } else {
                    replaceScalarsWithChaos(value);
                }
            }
        } else if (node.isArray()) {
            ArrayNode array = (ArrayNode) node;
            for (int i = 0; i < array.size(); i++) {
                JsonNode value = array.get(i);
                if (value.isTextual()) {
                    array.set(i, CHAOS_VALUE);
                } else if (value.isNumber()) {
                    array.set(i, CHAOS_VALUE_AS_NUMBER);
                } else {
                    replaceScalarsWithChaos(value);
                }
            }
        }
    }

    private boolean isThrottled(HttpResponseData response) {
        return SentinelHttpClient.THROTTLE_STATUS_CODES.contains(response.statusCode());
    }

    private Optional<Signature> matchSignature(String body) {
        for (Signature signature : SIGNATURES) {
            if (signature.pattern().matcher(body).find()) {
                return Optional.of(signature);
            }
        }
        return Optional.empty();
    }

    private Finding buildFinding(Endpoint endpoint, String parameter, String payload, Signature signature) {
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.VERBOSE_ERROR_DISCLOSURE,
                signature.severity(),
                endpoint.url(),
                endpoint.method().name(),
                parameter,
                payload,
                "An oversized value sent to '" + parameter + "' triggered a response containing "
                        + signature.label() + " instead of a generic error message.",
                "Response to " + endpoint.method() + " " + endpoint.url() + " matched " + signature.label()
                        + " - the matched text itself is not included in this report, since it may "
                        + "contain internal file paths or class names.",
                RECOMMENDATION
        );
    }
}
