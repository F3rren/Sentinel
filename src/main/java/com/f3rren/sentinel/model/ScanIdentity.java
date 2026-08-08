package com.f3rren.sentinel.model;

/**
 * A single caller-supplied credential to attach to every request Sentinel makes on its behalf -
 * e.g. {@code header="Authorization", value="Bearer <token>"} for one of the two identities the
 * IDOR module compares. Sentinel never generates or discovers credentials itself: the operator
 * supplies ones already valid for the target as part of the scan request.
 */
public record ScanIdentity(String header, String value) {
}
