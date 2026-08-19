package com.f3rren.sentinel.attack.jwt;

import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.ScanIdentity;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Checks whether the JWT supplied as a scan identity (see {@code POST /api/scans}'s {@code
 * identities} field) is signed with a common/well-known secret, by recomputing its HMAC signature
 * offline against a small, fixed dictionary and comparing the result byte-for-byte - no additional
 * request is ever sent to the target. Identity A is tried first, identity B otherwise; needs at
 * least one identity whose value actually looks like a JWT, so it's opt-in like BFLA and Mass
 * Assignment ({@code sentinel.scan.jwt-weak-secret.enabled=true}).
 * <p>
 * Only applies to HMAC-family algorithms ({@code HS256}/{@code HS384}/{@code HS512}) declared in
 * the token's own header - an RS/ES-signed token needs the issuer's private key, not a shared
 * secret, so it's silently skipped rather than guessed at. Each candidate secret is tried under
 * two key-derivation conventions: the raw secret bytes used directly as the HMAC key (the most
 * common real-world case), and {@code SHA-256(secret)} (a real, if less common, convention some
 * frameworks use specifically to guarantee a fixed-length key regardless of how short an operator
 * sets the secret to). A target deriving its key some other way won't be caught by this even if
 * the underlying secret is genuinely weak - a known, documented limitation, not a false sense of
 * security about a target that happens to do that.
 * <p>
 * Deliberately does not fully decode/log the captured token anywhere in a finding: only the
 * algorithm and the cracked secret (the actionable fact an operator needs to fix this) are
 * reported, not the token's own claims.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 3)
@ConditionalOnProperty(prefix = "sentinel.scan.jwt-weak-secret", name = "enabled", havingValue = "true", matchIfMissing = false)
public class JwtWeakSecretScanner implements AttackModule {

    private static final Logger log = LoggerFactory.getLogger(JwtWeakSecretScanner.class);

    // A short, well-known list of secrets that show up over and over in real deployments -
    // placeholders from documentation/examples/tutorials that get shipped as-is. Kept small and
    // fixed, the same philosophy as the brute-force module's credential list, rather than an
    // exhaustive wordlist: this only needs to catch the common, careless case fast.
    private static final List<String> CANDIDATE_SECRETS = List.of(
            "secret", "changeme", "password", "", "jwtsecret", "your-256-bit-secret",
            "test", "dev", "development", "supersecret", "mysecretkey", "secretkey",
            "12345678", "qwertyuiop", "jwt_secret"
    );

    private static final Map<String, String> HMAC_ALGORITHMS = Map.of(
            "HS256", "HmacSHA256",
            "HS384", "HmacSHA384",
            "HS512", "HmacSHA512"
    );

    private static final String RECOMMENDATION =
            "Generate the JWT signing secret with a cryptographically secure random generator "
            + "(at least 256 bits for HS256), never a placeholder, dictionary word, or example "
            + "value copied from documentation. Keep it only in a secrets manager or "
            + "environment-specific configuration that is never committed, and rotate it - "
            + "invalidating every previously issued token - if it may have been exposed.";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private List<Finding> pendingFindings = List.of();

    @Override
    public String name() {
        return "jwt-weak-secret";
    }

    @Override
    public void beginScan(ScanContext context) {
        // Endpoint-independent by nature (it never sends a request), so the whole check runs
        // once here rather than being spread across scan(Endpoint) calls.
        pendingFindings = computeFindings(context);
    }

    @Override
    public List<Finding> scan(Endpoint endpoint) {
        return List.of();
    }

    @Override
    public List<Finding> endScan() {
        List<Finding> findings = pendingFindings;
        pendingFindings = List.of();
        return findings;
    }

    private List<Finding> computeFindings(ScanContext context) {
        if (context == null) {
            return List.of();
        }
        String label = context.identityA() != null ? "identity A" : "identity B";
        String token = extractJwt(context.identityA())
                .or(() -> extractJwt(context.identityB()))
                .orElse(null);
        if (token == null) {
            return List.of();
        }

        String[] parts = token.split("\\.");
        String algorithm;
        try {
            String headerJson = new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8);
            JsonNode header = objectMapper.readTree(headerJson);
            algorithm = header.path("alg").asText("");
        } catch (Exception e) {
            return List.of();
        }
        String hmacAlgorithm = algorithm.isEmpty() ? null : HMAC_ALGORITHMS.get(algorithm.toUpperCase(Locale.ROOT));
        if (hmacAlgorithm == null) {
            // Not HMAC-signed (RS/ES/none/unrecognized) - nothing a shared-secret dictionary
            // check can meaningfully say about it.
            return List.of();
        }

        String signingInput = parts[0] + "." + parts[1];
        byte[] actualSignature;
        try {
            actualSignature = base64UrlDecode(parts[2]);
        } catch (Exception e) {
            return List.of();
        }

        for (String candidate : CANDIDATE_SECRETS) {
            for (KeyDerivation derivation : derivedKeys(candidate)) {
                byte[] computed = hmac(hmacAlgorithm, derivation.key(), signingInput);
                if (computed != null && MessageDigest.isEqual(computed, actualSignature)) {
                    return List.of(buildFinding(label, algorithm, candidate, derivation.description()));
                }
            }
        }
        return List.of();
    }

    private record KeyDerivation(String description, byte[] key) {
    }

    /**
     * The raw secret bytes used directly as the HMAC key (skipped when the secret is empty - Java's
     * own {@link SecretKeySpec} rejects a zero-length key, and no meaningful real-world HMAC
     * implementation accepts one either), plus {@code SHA-256(secret)} - always a valid non-empty
     * key regardless of how short or empty the original secret is.
     */
    private List<KeyDerivation> derivedKeys(String secret) {
        byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
        byte[] hashed;
        try {
            hashed = MessageDigest.getInstance("SHA-256").digest(raw);
        } catch (Exception e) {
            return List.of();
        }
        if (raw.length == 0) {
            return List.of(new KeyDerivation("SHA-256 of the secret used as the HMAC key", hashed));
        }
        return List.of(
                new KeyDerivation("the raw secret used directly as the HMAC key", raw),
                new KeyDerivation("SHA-256 of the secret used as the HMAC key", hashed)
        );
    }

    private Finding buildFinding(String identityLabel, String algorithm, String crackedSecret, String derivationDescription) {
        String displaySecret = crackedSecret.isEmpty() ? "<empty string>" : crackedSecret;
        return new Finding(
                UUID.randomUUID().toString(),
                name(),
                VulnerabilityType.WEAK_JWT_SECRET,
                Severity.CRITICAL,
                "",
                "",
                "",
                displaySecret,
                "The JWT supplied as a scan identity is signed with a common/well-known secret, "
                        + "recovered via an offline dictionary check against its own signature.",
                "The " + algorithm + " signature of the token supplied as " + identityLabel
                        + " matches HMAC(" + algorithm + ", '" + displaySecret + "') with " + derivationDescription
                        + " - no request was sent to the target to determine this. Anyone with this "
                        + "secret can forge a valid token for any user.",
                RECOMMENDATION
        );
    }

    private Optional<String> extractJwt(ScanIdentity identity) {
        if (identity == null || identity.value() == null) {
            return Optional.empty();
        }
        String value = identity.value().trim();
        String token = value.regionMatches(true, 0, "Bearer ", 0, 7) ? value.substring(7).trim() : value;
        if (token.split("\\.").length != 3) {
            return Optional.empty();
        }
        return Optional.of(token);
    }

    private byte[] hmac(String algorithm, byte[] key, String signingInput) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.debug("HMAC computation failed for a candidate key: {}", e.getMessage());
            return null;
        }
    }

    private static byte[] base64UrlDecode(String value) {
        String padded = value + "=".repeat((4 - value.length() % 4) % 4);
        return Base64.getUrlDecoder().decode(padded);
    }
}
