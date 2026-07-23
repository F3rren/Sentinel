package com.f3rren.sentinel.web.dto;

import jakarta.validation.constraints.NotBlank;

public record ScanRequest(
        @NotBlank(message = "targetUrl e' obbligatorio") String targetUrl
) {
}
