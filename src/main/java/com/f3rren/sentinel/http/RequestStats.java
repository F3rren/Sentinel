package com.f3rren.sentinel.http;

/**
 * Snapshot of how many requests {@link SentinelHttpClient} has sent since the last
 * {@link SentinelHttpClient#resetRequestStats()}, and how many of those came back throttled
 * (429/423). Lets a caller (e.g. {@code ScanService}) tell "the target has nothing wrong with
 * it" apart from "the target started throttling partway through and the rest of the results are
 * unreliable" - two very different situations that otherwise both look like a clean report.
 */
public record RequestStats(int total, int throttled) {

    public double throttledRatio() {
        return total == 0 ? 0.0 : (double) throttled / total;
    }
}
