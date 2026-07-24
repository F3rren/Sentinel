package com.f3rren.sentinel.attack.sqli;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.AttackModule;
import com.f3rren.sentinel.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * sentinel.scan.sql-injection.enabled=false must keep the bean from being created at all,
 * not merely skip it at scan time - and ScanService (which depends on List<AttackModule>)
 * must still start cleanly with zero modules registered, since disabling the only module
 * currently implemented is a legitimate configuration, not a startup failure.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = "sentinel.scan.sql-injection.enabled=false")
class SqlInjectionScannerDisabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private ScanService scanService;

    @Test
    void moduleIsNotRegisteredWhenDisabled() {
        assertThat(applicationContext.getBeanNamesForType(AttackModule.class)).isEmpty();
        assertThat(scanService).isNotNull();
    }
}
