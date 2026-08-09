package com.f3rren.sentinel.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * One caller-supplied identity: an HTTP header name/value pair Sentinel attaches to every
 * request it makes on that identity's behalf (e.g. {@code header="Authorization",
 * value="Bearer <token>"}). Sentinel never generates or discovers credentials itself.
 */
public record IdentityRequest(
        @NotBlank(message = "identities.a/b.header e' obbligatorio se fornito") String header,
        @NotBlank(message = "identities.a/b.value e' obbligatorio se fornito") String value
) {
}
