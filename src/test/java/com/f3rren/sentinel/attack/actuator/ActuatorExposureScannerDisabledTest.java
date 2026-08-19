package com.f3rren.sentinel.attack.actuator;

import com.f3rren.sentinel.SentinelApplication;
import com.f3rren.sentinel.attack.bruteforce.BruteForceScanner;
import com.f3rren.sentinel.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mirrors the other per-module disabled tests: disabling actuator-exposure must not affect the
 * other modules.
 */
@SpringBootTest(classes = SentinelApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = "sentinel.scan.actuator-exposure.enabled=false")
class ActuatorExposureScannerDisabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private ScanService scanService;

    @Test
    void onlyThisModuleIsNotRegisteredWhenDisabled() {
        assertThat(applicationContext.getBeanNamesForType(ActuatorExposureScanner.class)).isEmpty();
        assertThat(applicationContext.getBeanNamesForType(BruteForceScanner.class)).isNotEmpty();
        assertThat(scanService).isNotNull();
    }
}
