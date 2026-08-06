package com.f3rren.sentinel.attack;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.authn.MissingAuthenticationScanner;
import com.f3rren.sentinel.attack.bruteforce.BruteForceScanner;
import com.f3rren.sentinel.attack.misconfig.SecurityMisconfigurationScanner;
import com.f3rren.sentinel.attack.ratelimit.RateLimitScanner;
import com.f3rren.sentinel.attack.sqli.SqlInjectionScanner;
import com.f3rren.sentinel.attack.xss.XssScanner;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * With no per-module property overridden, every attack module ships enabled - the switches
 * are opt-out (sentinel.scan.&lt;module&gt;.enabled=false), not opt-in.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AttackModuleEnablementTest {

    @Autowired
    private List<AttackModule> attackModules;

    @Test
    void everyModuleIsRegisteredByDefault() {
        assertThat(attackModules).hasSize(6);
        assertThat(attackModules).hasAtLeastOneElementOfType(SqlInjectionScanner.class);
        assertThat(attackModules).hasAtLeastOneElementOfType(MissingAuthenticationScanner.class);
        assertThat(attackModules).hasAtLeastOneElementOfType(BruteForceScanner.class);
        assertThat(attackModules).hasAtLeastOneElementOfType(SecurityMisconfigurationScanner.class);
        assertThat(attackModules).hasAtLeastOneElementOfType(XssScanner.class);
        assertThat(attackModules).hasAtLeastOneElementOfType(RateLimitScanner.class);
    }

    @Test
    void rateLimitScannerIsOrderedLast() {
        // ScanService runs each module across every endpoint before the next module starts
        // (module-outer nesting) specifically so RateLimitScanner's bucket-exhausting burst
        // doesn't starve the other modules' single requests on endpoints tested later. That
        // guarantee only holds if Spring actually honors @Order when injecting this list.
        assertThat(attackModules.get(attackModules.size() - 1)).isInstanceOf(RateLimitScanner.class);
    }
}
