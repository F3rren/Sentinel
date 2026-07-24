package com.f3rren.sentinel.discovery;

import java.util.UUID;

/**
 * Generic placeholder values sent for fields discovery can't infer anything more specific
 * about (an untyped form field, a JSON Schema string property with no format/enum). Deliberately
 * not a plain word like "test" or "widget": a random, clearly-synthetic token both avoids reading
 * as ordinary manual QA data and makes traffic/data Sentinel produced easy to recognize and clean
 * up afterward, in the target's logs or database, by searching for the "sentinel-" prefix.
 */
public final class SampleValues {

    private SampleValues() {
    }

    public static String randomToken() {
        return "sentinel-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /**
     * {@code .invalid} is reserved by RFC 2606 to never resolve - safer than a real-looking
     * domain for a value that may get persisted or, worse, actually emailed to.
     */
    public static String randomEmail() {
        return randomToken() + "@sentinel.invalid";
    }
}
