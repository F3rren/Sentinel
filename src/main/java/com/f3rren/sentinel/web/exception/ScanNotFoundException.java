package com.f3rren.sentinel.web.exception;

public class ScanNotFoundException extends RuntimeException {

    public ScanNotFoundException(String scanId) {
        super("Scan non trovato: " + scanId);
    }
}
