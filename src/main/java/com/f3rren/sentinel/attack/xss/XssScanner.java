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
            "Applicare output encoding contestuale su ogni input riflesso nella risposta (HTML entity "
            + "encoding per contenuto renderizzato in pagine HTML, encoding corretto dei valori nelle "
            + "risposte JSON) - non basarsi sulla sola validazione lato client. Impostare un "
            + "Content-Type esplicito e coerente su ogni risposta, con X-Content-Type-Options: nosniff, "
            + "cosi' un browser non tenta di interpretare come HTML una risposta pensata come dati puri "
            + "(es. JSON). Dove possibile, una Content-Security-Policy che limiti gli script inline "
            + "riduce l'impatto anche in caso di encoding mancante.";

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
                    ? "Il parametro '" + param.name() + "' viene riflesso senza encoding in una risposta "
                            + "con Content-Type HTML (o assente): un browser eseguirebbe lo script iniettato."
                    : "Il parametro '" + param.name() + "' viene riflesso senza encoding nella risposta, ma "
                            + "il Content-Type non e' HTML: non direttamente exploitable tramite questa "
                            + "risposta, ma indica assenza di output encoding sull'input riflesso.";

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
                    "Payload riflesso invariato nel corpo della risposta (Content-Type: "
                            + response.header("content-type").orElse("assente") + ").",
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
