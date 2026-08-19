package com.f3rren.sentinel.attack.jwt;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.AttackModule;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mirrors the *EnabledTest pattern used by the other opt-in modules: proves the property actually
 * wires the bean in, and that ScanService picks it up like any other module.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = "sentinel.scan.jwt-weak-secret.enabled=true")
class JwtWeakSecretScannerEnabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private List<AttackModule> attackModules;

    @Test
    void isRegisteredWhenExplicitlyEnabled() {
        assertThat(applicationContext.getBeanNamesForType(JwtWeakSecretScanner.class)).isNotEmpty();
        assertThat(attackModules).hasAtLeastOneElementOfType(JwtWeakSecretScanner.class);
    }
}
