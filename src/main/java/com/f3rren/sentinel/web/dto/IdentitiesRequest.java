package com.f3rren.sentinel.web.dto;

import jakarta.validation.Valid;

/**
 * Optional two-identity credentials an operator can attach to a scan request so the IDOR module
 * has something to compare. Absent entirely (the default), the scan runs fully anonymous as
 * before and the IDOR module stays a no-op.
 */
public record IdentitiesRequest(@Valid IdentityRequest a, @Valid IdentityRequest b) {
}
