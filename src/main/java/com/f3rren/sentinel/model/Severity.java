package com.f3rren.sentinel.model;

/**
 * Severity of a finding, ordered from least to most critical.
 * Ordinal order is relied upon for comparisons (e.g. computing the highest severity in a report).
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
