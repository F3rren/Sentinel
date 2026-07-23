package com.f3rren.sentinel.attack;

import com.f3rren.sentinel.model.Endpoint;
import com.f3rren.sentinel.model.Finding;

import java.util.List;

/**
 * A pluggable attack technique. Each module fuzzes a single discovered endpoint
 * and reports back any findings; implementations must not throw on a per-endpoint
 * failure so one broken target page does not abort the whole scan.
 */
public interface AttackModule {

    String name();

    List<Finding> scan(Endpoint endpoint);
}
