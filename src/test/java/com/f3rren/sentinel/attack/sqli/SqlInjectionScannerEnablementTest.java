package com.f3rren.sentinel.attack.sqli;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.AttackModule;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the sentinel.scan.sql-injection.enabled switch controls whether the module bean
 * exists at all - not just whether it happens to find something - since ScanService simply
 * runs whatever ends up in the autowired List<AttackModule>.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class SqlInjectionScannerEnablementTest {

    @Autowired
    private List<AttackModule> attackModules;

    @Test
    void moduleIsRegisteredByDefault() {
        assertThat(attackModules).hasSize(1);
        assertThat(attackModules.get(0)).isInstanceOf(SqlInjectionScanner.class);
    }
}
