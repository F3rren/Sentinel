package com.f3rren.sentinel.attack.bfla;

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
 * Mirrors the *DisabledTest pattern used by every other module, but inverted: proves the opt-in
 * property actually wires the bean in, and that ScanService picks it up like any other module.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = "sentinel.scan.bfla.enabled=true")
class BflaScannerEnabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private List<AttackModule> attackModules;

    @Test
    void isRegisteredWhenExplicitlyEnabled() {
        assertThat(applicationContext.getBeanNamesForType(BflaScanner.class)).isNotEmpty();
        assertThat(attackModules).hasAtLeastOneElementOfType(BflaScanner.class);
    }
}
