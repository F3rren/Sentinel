package com.f3rren.sentinel.attack.jwt;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.sqli.SqlInjectionScanner;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Like IdorScanner, BflaScanner and MassAssignmentScanner, JwtWeakSecretScanner is opt-in
 * (matchIfMissing = false in its {@code @ConditionalOnProperty}): it needs an identity whose value
 * actually looks like a JWT, which most scans never supply, so it must not exist as a bean - let
 * alone run - unless an operator explicitly turns it on with
 * {@code sentinel.scan.jwt-weak-secret.enabled=true}.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class JwtWeakSecretScannerDisabledByDefaultTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void isNotRegisteredWithoutBeingExplicitlyEnabled() {
        assertThat(applicationContext.getBeanNamesForType(JwtWeakSecretScanner.class)).isEmpty();
        // Every opt-out module is unaffected: this module's different default doesn't change theirs.
        assertThat(applicationContext.getBeanNamesForType(SqlInjectionScanner.class)).isNotEmpty();
    }
}
