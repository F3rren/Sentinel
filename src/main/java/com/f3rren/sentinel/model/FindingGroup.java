package com.f3rren.sentinel.model;

import java.util.List;

/**
 * Every {@link Finding} sharing the same module/type/description/recommendation, collapsed into
 * one entry with a list of {@link FindingOccurrence}s instead of one full (and mostly duplicate)
 * object per affected endpoint - a scan flagging the same missing-rate-limiting issue on twenty
 * endpoints produces one {@code FindingGroup} with twenty occurrences, not twenty near-identical
 * findings repeating the same description and recommendation text.
 */
public record FindingGroup(
        String module,
        VulnerabilityType type,
        String description,
        String recommendation,
        List<FindingOccurrence> occurrences
) {
}
