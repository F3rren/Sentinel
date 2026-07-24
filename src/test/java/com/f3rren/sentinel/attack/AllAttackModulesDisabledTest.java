package com.f3rren.sentinel.attack;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ScanService depends on List&lt;AttackModule&gt;, which must not be a hard requirement:
 * disabling every module (a legitimate, if unusual, configuration) must not prevent the app
 * from starting.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = {
        "sentinel.scan.sql-injection.enabled=false",
        "sentinel.scan.missing-authentication.enabled=false"
})
class AllAttackModulesDisabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private ScanService scanService;

    @Test
    void appStartsCleanlyWithZeroAttackModules() {
        assertThat(applicationContext.getBeanNamesForType(AttackModule.class)).isEmpty();
        assertThat(scanService).isNotNull();
    }
}
