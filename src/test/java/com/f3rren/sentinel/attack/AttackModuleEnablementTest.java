package com.f3rren.sentinel.attack;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.authn.MissingAuthenticationScanner;
import com.f3rren.sentinel.attack.sqli.SqlInjectionScanner;
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
        assertThat(attackModules).hasSize(2);
        assertThat(attackModules).hasAtLeastOneElementOfType(SqlInjectionScanner.class);
        assertThat(attackModules).hasAtLeastOneElementOfType(MissingAuthenticationScanner.class);
    }
}
