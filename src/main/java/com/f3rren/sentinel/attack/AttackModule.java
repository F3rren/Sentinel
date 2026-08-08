package com.f3rren.sentinel.attack;

import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;
import com.f3rren.sentinel.model.ScanContext;

import java.util.List;

/**
 * A pluggable attack technique. Each module fuzzes a single discovered endpoint
 * and reports back any findings; implementations must not throw on a per-endpoint
 * failure so one broken target page does not abort the whole scan.
 */
public interface AttackModule {

    String name();

    List<Finding> scan(Endpoint endpoint);

    /**
     * Called once before this module's endpoint loop starts for a given scan, carrying that
     * scan's context (currently: the optional identities an operator supplied - see {@code
     * POST /api/scans}'s {@code identities} field). Default no-op: only a module that needs
     * cross-endpoint or per-scan state (today, only the IDOR module) needs to override it.
     */
    default void beginScan(ScanContext context) {
    }

    /**
     * Called once after this module has run against every endpoint in the scan, so a stateful
     * module can discard whatever it accumulated during {@link #scan(Endpoint)} calls. This
     * matters because modules are singleton Spring beans shared across every scan Sentinel ever
     * runs: anything held between {@link #beginScan(ScanContext)} and here must not leak into
     * the next one.
     */
    default void endScan() {
    }
}
