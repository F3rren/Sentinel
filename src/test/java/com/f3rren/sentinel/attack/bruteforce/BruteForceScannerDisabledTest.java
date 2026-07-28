package com.f3rren.sentinel.attack.bruteforce;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.authn.MissingAuthenticationScanner;
import com.f3rren.sentinel.attack.sqli.SqlInjectionScanner;
import com.f3rren.sentinel.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mirrors the other per-module disabled tests: disabling brute-force must not affect the
 * other two modules.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = "sentinel.scan.brute-force.enabled=false")
class BruteForceScannerDisabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private ScanService scanService;

    @Test
    void onlyThisModuleIsNotRegisteredWhenDisabled() {
        assertThat(applicationContext.getBeanNamesForType(BruteForceScanner.class)).isEmpty();
        assertThat(applicationContext.getBeanNamesForType(SqlInjectionScanner.class)).isNotEmpty();
        assertThat(applicationContext.getBeanNamesForType(MissingAuthenticationScanner.class)).isNotEmpty();
        assertThat(scanService).isNotNull();
    }
}
