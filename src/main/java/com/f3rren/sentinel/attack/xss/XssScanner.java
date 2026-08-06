package com.f3rren.sentinel.attack.xss;

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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Fuzzes each discovered parameter with a handful of classic XSS markers and checks whether the
 * exact payload comes back unescaped in the response body - a plain substring check, same style
 * as {@link com.f3rren.sentinel.attack.sqli.SqlInjectionScanner}'s error-signature matching, since
 * the payloads are synthetic strings ("sentinel-xss") unlikely to appear in legitimate content.
 * <p>
 * Unescaped reflection alone is not the whole story: a browser only executes it if the response
 * is actually rendered as HTML. Most targets here are JSON APIs, where {@code <script>} inside a
 * JSON string value is inert - the browser never parses it as markup. So the finding is split by
 * how the response identifies itself: {@code Content-Type} missing or containing "html" means a
 * browser could plausibly render the body directly, hence a real, exploitable
 * {@link VulnerabilityType#REFLECTED_XSS} (HIGH); anything else (JSON, plain text, ...) is
 * downgraded to {@link VulnerabilityType#UNSANITIZED_INPUT_REFLECTION} (LOW) - a genuine missing
 * output-encoding defect, but not one this response alone can turn into script execution.
 */
@Component
@Order(4)
@ConditionalOnProperty(prefix = "sentinel.scan.xss", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(XssScanner.class);

    private static final String RECOMMENDATION =
            "Apply contextual output encoding to every input reflected in the response (HTML entity "
            + "encoding for content rendered in HTML pages, correct encoding of values in JSON "
            + "responses) - do not rely on client-side validation alone. Set an explicit, consistent "
            + "Content-Type on every response, together with X-Content-Type-Options: nosniff, so a "
            + "browser does not attempt to interpret as HTML a response meant to be pure data (e.g. "
            + "JSON). Where possible, a Content-Security-Policy that restricts inline scripts reduces "
            + "the impact even when encoding is missing.";

    private static final List<String> PAYLOADS = List.of(
            "<script>alert('sentinel-xss')</script>",
            "\"><script>alert('sentinel-xss')</script>",
            "<img src=x onerror=alert('sentinel-xss')>",
            "<svg onload=alert('sentinel-xss')>"
    );

    private final SentinelHttpClient httpClient;

    public XssScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "xss";
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
                log.warn("XSS check failed for {} {} param={}: {}", endpoint.method(), endpoint.url(), param.name(), e.getMessage());
            }
        }
        return findings;
    }

    private Optional<Finding> checkParam(Endpoint endpoint, EndpointParam param, Map<String, String> baselineParams) throws Exception {
        for (String payload : PAYLOADS) {
            Map<String, String> params = new LinkedHashMap<>(baselineParams);
            params.put(param.name(), payload);
            HttpResponseData response = httpClient.exchange(endpoint.method(), endpoint.url(), params, endpoint.requestBodySample());

            if (!response.bodyOrEmpty().contains(payload)) {
                continue;
            }

            boolean htmlRenderable = isHtmlRenderable(response);
            VulnerabilityType type = htmlRenderable ? VulnerabilityType.REFLECTED_XSS : VulnerabilityType.UNSANITIZED_INPUT_REFLECTION;
            Severity severity = htmlRenderable ? Severity.HIGH : Severity.LOW;
            String description = htmlRenderable
                    ? "Parameter '" + param.name() + "' is reflected without encoding in a response "
                            + "with an HTML (or missing) Content-Type: a browser would execute the injected script."
                    : "Parameter '" + param.name() + "' is reflected without encoding in the response, but "
                            + "the Content-Type is not HTML: not directly exploitable through this "
                            + "response, but indicates a lack of output encoding on the reflected input.";

            return Optional.of(new Finding(
                    UUID.randomUUID().toString(),
                    name(),
                    type,
                    severity,
                    endpoint.url(),
                    endpoint.method().name(),
                    param.name(),
                    payload,
                    description,
                    "Payload reflected unchanged in the response body (Content-Type: "
                            + response.header("content-type").orElse("missing") + ").",
                    RECOMMENDATION
            ));
        }
        return Optional.empty();
    }

    private static boolean isHtmlRenderable(HttpResponseData response) {
        Optional<String> contentType = response.header("content-type");
        if (contentType.isEmpty()) {
            return true;
        }
        return contentType.get().toLowerCase(Locale.ROOT).contains("html");
    }
}
