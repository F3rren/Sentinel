package com.f3rren.sentinel.attack.misconfig;

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
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Flags common security-relevant misconfigurations visible on an ordinary, successful response:
 * missing defense-in-depth headers, a CORS policy that reflects an arbitrary Origin (worse still
 * paired with credentials), and a Server/X-Powered-By banner that discloses implementation
 * details. None of this fuzzes anything - it inspects one legitimate GET (plus, for CORS, one
 * extra GET carrying a hostile Origin header) per endpoint, so unlike the other modules it is
 * read-only by construction and needs no ordering relative to state-mutating checks.
 */
@Component
@Order(3)
@ConditionalOnProperty(prefix = "sentinel.scan.security-misconfiguration", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityMisconfigurationScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(SecurityMisconfigurationScanner.class);

    // Deliberately nothing like a real origin this API would ever legitimately allow, so any
    // reflection of it back in Access-Control-Allow-Origin is unambiguous evidence that the
    // policy trusts whatever Origin the caller sends instead of checking against an allow-list.
    private static final String PROBE_ORIGIN = "https://sentinel-cors-probe.invalid";

    private static final String MISSING_HEADERS_RECOMMENDATION =
            "Impostare gli header di sicurezza mancanti a livello di gateway (o in un filtro comune a "
            + "tutti i servizi), cosi' la protezione e' uniforme senza doverla ripetere in ogni "
            + "microservizio: X-Content-Type-Options: nosniff, X-Frame-Options: DENY (o CSP con "
            + "frame-ancestors), Content-Security-Policy con una policy adeguata al tipo di risposta "
            + "(un'API JSON puo' partire da default-src 'none'), e Strict-Transport-Security se il "
            + "servizio e' esposto anche su HTTPS.";

    private static final String PERMISSIVE_CORS_RECOMMENDATION =
            "Sostituire il riflesso indiscriminato dell'Origin (o il wildcard '*') con un allow-list "
            + "esplicito dei domini realmente autorizzati a chiamare l'API da browser. Se le richieste "
            + "devono portare credenziali (cookie, header Authorization), Access-Control-Allow-Origin "
            + "non puo' essere '*' per specifica CORS: va comunque ristretto a origini fidate.";

    private static final String SERVER_BANNER_RECOMMENDATION =
            "Rimuovere o oscurare l'header che espone tecnologia/versione del server (es. tramite "
            + "configurazione del gateway o del container HTTP), per non facilitare a un attaccante la "
            + "ricerca di CVE note per quella versione specifica.";

    private final SentinelHttpClient httpClient;

    public SecurityMisconfigurationScanner(SentinelHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "security-misconfiguration";
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        if (!HttpMethod.GET.equals(endpoint.method())) {
            return List.of();
        }

        Map<String, String> params = new LinkedHashMap<>();
        for (EndpointParam param : endpoint.params()) {
            params.put(param.name(), param.sampleValue());
        }

        HttpResponseData response;
        try {
            response = httpClient.exchange(endpoint.method(), endpoint.url(), params);
        } catch (Exception e) {
            log.warn("Security-misconfiguration check failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return List.of();
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();
        checkSecurityHeaders(endpoint, response).ifPresent(findings::add);
        checkBannerDisclosure(endpoint, response).ifPresent(findings::add);
        checkCors(endpoint).ifPresent(findings::add);
        return findings;
    }

    private Optional<Finding> checkSecurityHeaders(Endpoint endpoint, HttpResponseData response) {
        List<String> missing = new ArrayList<>();
        if (response.header("x-content-type-options").isEmpty()) {
            missing.add("X-Content-Type-Options");
        }
        if (response.header("x-frame-options").isEmpty()) {
            missing.add("X-Frame-Options");
        }
        if (response.header("content-security-policy").isEmpty()) {
            missing.add("Content-Security-Policy");
        }
        if (isHttps(endpoint.url()) && response.header("strict-transport-security").isEmpty()) {
            missing.add("Strict-Transport-Security");
        }

        if (missing.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.MISSING_SECURITY_HEADERS,
                Severity.LOW,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "La risposta non include uno o piu' header di sicurezza raccomandati.",
                "Header mancanti su " + endpoint.method() + " " + endpoint.url() + ": " + String.join(", ", missing) + ".",
                MISSING_HEADERS_RECOMMENDATION
        ));
    }

    private Optional<Finding> checkCors(Endpoint endpoint) {
        HttpResponseData corsResponse;
        try {
            corsResponse = httpClient.getWithHeader(endpoint.url(), "Origin", PROBE_ORIGIN);
        } catch (Exception e) {
            log.warn("CORS probe failed for {} {}: {}", endpoint.method(), endpoint.url(), e.getMessage());
            return Optional.empty();
        }

        Optional<String> allowOrigin = corsResponse.header("access-control-allow-origin");
        if (allowOrigin.isEmpty()) {
            return Optional.empty();
        }
        String value = allowOrigin.get();
        boolean reflectsArbitraryOrigin = value.equals(PROBE_ORIGIN) || value.equals("*");
        if (!reflectsArbitraryOrigin) {
            return Optional.empty();
        }

        boolean allowsCredentials = corsResponse.header("access-control-allow-credentials")
                .map(v -> v.equalsIgnoreCase("true"))
                .orElse(false);
        Severity severity = allowsCredentials ? Severity.HIGH : Severity.MEDIUM;

        return Optional.of(new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.PERMISSIVE_CORS,
                severity,
                endpoint.url(),
                endpoint.method().name(),
                "Origin",
                PROBE_ORIGIN,
                "La policy CORS accetta un Origin arbitrario invece di un allow-list di domini fidati.",
                "Richiesta con header 'Origin: " + PROBE_ORIGIN + "' su " + endpoint.method() + " " + endpoint.url()
                        + " ha ricevuto risposta 'Access-Control-Allow-Origin: " + value + "'"
                        + (allowsCredentials ? " insieme a 'Access-Control-Allow-Credentials: true'." : "."),
                PERMISSIVE_CORS_RECOMMENDATION
        ));
    }

    private Optional<Finding> checkBannerDisclosure(Endpoint endpoint, HttpResponseData response) {
        List<String> banners = new ArrayList<>();
        response.header("server").filter(SecurityMisconfigurationScanner::looksVersioned)
                .ifPresent(v -> banners.add("Server: " + v));
        response.header("x-powered-by").ifPresent(v -> banners.add("X-Powered-By: " + v));

        if (banners.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.SERVER_BANNER_DISCLOSURE,
                Severity.LOW,
                endpoint.url(),
                endpoint.method().name(),
                "",
                "",
                "La risposta rivela tecnologia e/o versione del server tramite header HTTP.",
                "Header rilevati su " + endpoint.method() + " " + endpoint.url() + ": " + String.join(", ", banners) + ".",
                SERVER_BANNER_RECOMMENDATION
        ));
    }

    private static boolean looksVersioned(String serverHeaderValue) {
        return serverHeaderValue.chars().anyMatch(Character::isDigit);
    }

    private static boolean isHttps(String url) {
        try {
            return "https".equalsIgnoreCase(URI.create(url).getScheme());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
