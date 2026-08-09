package com.f3rren.sentinel.model;

/**
 * Per-scan context handed to every {@link com.f3rren.sentinel.attack.AttackModule} via
 * {@code beginScan}, before that module's endpoint loop starts. Carries the two identities an
 * operator may optionally supply for a given scan (see {@code POST /api/scans}'s {@code
 * identities} field) - modules that don't need them (every module except the IDOR one, today)
 * simply never look at it.
 */
public record ScanContext(ScanIdentity identityA, ScanIdentity identityB) {

    public static final ScanContext EMPTY = new ScanContext(null, null);

    public boolean hasBothIdentities() {
        return identityA != null && identityB != null;
    }
}
