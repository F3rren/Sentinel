package com.f3rren.sentinel.attack.authn;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.sqli.SqlInjectionScanner;
import com.f3rren.sentinel.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mirrors SqlInjectionScannerDisabledTest for the other module: disabling
 * missing-authentication must not affect sql-injection.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = "sentinel.scan.missing-authentication.enabled=false")
class MissingAuthenticationScannerDisabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private ScanService scanService;

    @Test
    void onlyThisModuleIsNotRegisteredWhenDisabled() {
        assertThat(applicationContext.getBeanNamesForType(MissingAuthenticationScanner.class)).isEmpty();
        assertThat(applicationContext.getBeanNamesForType(SqlInjectionScanner.class)).isNotEmpty();
        assertThat(scanService).isNotNull();
    }
}
