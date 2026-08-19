package com.f3rren.sentinel.attack.jwt;

import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;
import com.f3rren.sentinel.model.ScanIdentity;
import com.f3rren.sentinel.model.Severity;
import com.f3rren.sentinel.model.VulnerabilityType;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Builds real HS256/HS384-signed JWTs by hand (base64url-encode a header/payload, HMAC-sign,
 * base64url-encode the signature) rather than pulling in a JWT library just for tests - mirrors
 * how the scanner itself only ever needs {@code javax.crypto}, never a JWT parser.
 */
class JwtWeakSecretScannerTest {

    private final JwtWeakSecretScanner scanner = new JwtWeakSecretScanner();

    @Test
    void flagsATokenSignedWithADictionarySecret() {
        String token = sign("HS256", "HmacSHA256", "changeme");
        ScanContext context = identityAContext(token);

        List<Finding> findings = runFullScan(context);

        assertThat(findings).hasSize(1);
        Finding finding = findings.get(0);
        assertThat(finding.type()).isEqualTo(VulnerabilityType.WEAK_JWT_SECRET);
        assertThat(finding.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(finding.payload()).isEqualTo("changeme");
    }

    @Test
    void detectsHs384SignedTokensToo() {
        String token = sign("HS384", "HmacSHA384", "supersecret");
        ScanContext context = identityAContext(token);

        List<Finding> findings = runFullScan(context);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).payload()).isEqualTo("supersecret");
    }

    @Test
    void detectsADictionarySecretEvenWhenTheTargetPreHashesItIntoTheKey() {
        // Mirrors aquarium-ms's own JwtTokenProvider, which signs with SHA-256(secret) rather
        // than the raw secret bytes - the second key derivation the scanner tries.
        String token = signPreHashed("HS256", "HmacSHA256", "changeme");
        ScanContext context = identityAContext(token);

        List<Finding> findings = runFullScan(context);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).payload()).isEqualTo("changeme");
        assertThat(findings.get(0).evidence()).contains("SHA-256 of the secret");
    }

    @Test
    void detectsTheEmptySecretOnlyViaItsPreHashedForm() {
        // The empty string can never be a valid raw HMAC key (SecretKeySpec rejects a zero-length
        // key) - SHA-256("") is still a well-known, perfectly valid 32-byte key though.
        String token = signPreHashed("HS256", "HmacSHA256", "");
        ScanContext context = identityAContext(token);

        List<Finding> findings = runFullScan(context);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).payload()).isEqualTo("<empty string>");
    }

    @Test
    void reportsNothingForAStrongRandomSecretNotInTheDictionary() {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String strongSecret = Base64.getEncoder().encodeToString(random);
        String token = sign("HS256", "HmacSHA256", strongSecret);
        ScanContext context = identityAContext(token);

        assertThat(runFullScan(context)).isEmpty();
    }

    @Test
    void skipsNonHmacAlgorithms() {
        // A syntactically well-formed 3-part token declaring RS256 - no shared-secret dictionary
        // check applies, regardless of what garbage sits in the "signature" segment.
        String header = base64Url("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"1\"}");
        String token = header + "." + payload + "." + base64Url("not-a-real-signature");
        ScanContext context = identityAContext(token);

        assertThat(runFullScan(context)).isEmpty();
    }

    @Test
    void reportsNothingWithoutAnyIdentity() {
        assertThat(runFullScan(ScanContext.EMPTY)).isEmpty();
    }

    @Test
    void reportsNothingWhenTheIdentityValueIsNotJwtShaped() {
        ScanContext context = new ScanContext(new ScanIdentity("X-Api-Key", "not-a-jwt-at-all"), null);

        assertThat(runFullScan(context)).isEmpty();
    }

    @Test
    void fallsBackToIdentityBWhenIdentityAIsAbsent() {
        String token = sign("HS256", "HmacSHA256", "secret");
        ScanContext context = new ScanContext(null, new ScanIdentity("Authorization", "Bearer " + token));

        List<Finding> findings = runFullScan(context);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).evidence()).contains("identity B");
    }

    @Test
    void scanReturnsNothingDirectlyBecauseTheCheckIsEndpointIndependent() {
        // scan(Endpoint) must always be a no-op: the whole check runs once in beginScan/endScan.
        scanner.beginScan(identityAContext(sign("HS256", "HmacSHA256", "secret")));
        assertThat(scanner.scan(null)).isEmpty();
    }

    private List<Finding> runFullScan(ScanContext context) {
        scanner.beginScan(context);
        return scanner.endScan();
    }

    private ScanContext identityAContext(String token) {
        return new ScanContext(new ScanIdentity("Authorization", "Bearer " + token), null);
    }

    private String sign(String alg, String javaAlgorithm, String secret) {
        return sign(alg, javaAlgorithm, secret.getBytes(StandardCharsets.UTF_8));
    }

    private String signPreHashed(String alg, String javaAlgorithm, String secret) {
        try {
            byte[] hashed = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
            return sign(alg, javaAlgorithm, hashed);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String sign(String alg, String javaAlgorithm, byte[] key) {
        String header = base64Url("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"1\"}");
        String signingInput = header + "." + payload;
        byte[] signature = hmac(javaAlgorithm, key, signingInput);
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }

    private byte[] hmac(String algorithm, byte[] key, String signingInput) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
