package com.f3rren.sentinel.attack.bfla;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.sqli.SqlInjectionScanner;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Like IdorScanner, BflaScanner is opt-in (matchIfMissing = false in its
 * {@code @ConditionalOnProperty}): it's only meaningful once identities are supplied, which most
 * scans never do, so it must not exist as a bean - let alone run - unless an operator explicitly
 * turns it on with {@code sentinel.scan.bfla.enabled=true}.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class BflaScannerDisabledByDefaultTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void isNotRegisteredWithoutBeingExplicitlyEnabled() {
        assertThat(applicationContext.getBeanNamesForType(BflaScanner.class)).isEmpty();
        // Every opt-out module is unaffected: BFLA's different default doesn't change theirs.
        assertThat(applicationContext.getBeanNamesForType(SqlInjectionScanner.class)).isNotEmpty();
    }
}
