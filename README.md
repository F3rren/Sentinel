# Sentinel

Sentinel is an **automated security testing** tool: given an application's address (e.g. `localhost:8080`), it discovers the exposed endpoints and launches automated attacks to find vulnerabilities, returning a report with severity and remediation guidance.

> **Intended use**: only against applications you are authorized to security-test (your own projects, staging environments, an authorized pentest target). Do not point it at third-party systems without explicit consent.

## What it does today

1. **Endpoint discovery**, in two phases: **OpenAPI/Swagger** (preferred) - reads a spec at `/v3/api-docs` or similar, follows gateway aggregation across multiple services, and generates a type-aware JSON request body from the schema so write endpoints get a real, processable request instead of an immediate 415/400. **HTML crawling** - a fallback/supplement that parses links with a query string and forms.

2. **Attack**, fifteen modules:

   | Module | Findings (severity) | Default |
   |---|---|---|
   | SQL Injection | `SQL_INJECTION_ERROR_BASED` (CRITICAL), `SQL_INJECTION_BOOLEAN_BASED` (HIGH) | opt-out |
   | Missing Authentication | `MISSING_AUTHENTICATION` (HIGH mutating / MEDIUM otherwise) | opt-out |
   | Brute Force | `WEAK_CREDENTIALS` (CRITICAL), `MISSING_BRUTE_FORCE_PROTECTION` (LOW) | opt-out |
   | Security Misconfiguration | `MISSING_SECURITY_HEADERS` (LOW), `PERMISSIVE_CORS` (MEDIUM/HIGH), `SERVER_BANNER_DISCLOSURE` (LOW) | opt-out |
   | XSS | `REFLECTED_XSS` (HIGH), `UNSANITIZED_INPUT_REFLECTION` (LOW) | opt-out |
   | Excessive Data Exposure | `EXCESSIVE_DATA_EXPOSURE` (CRITICAL/HIGH) | opt-out |
   | Verbose Error Disclosure | `VERBOSE_ERROR_DISCLOSURE` (HIGH/MEDIUM) | opt-out |
   | Actuator Exposure | `EXPOSED_ACTUATOR_ENDPOINT` (CRITICAL → LOW, by endpoint ID) | opt-out |
   | Sensitive File Exposure | `EXPOSED_SENSITIVE_FILE` (CRITICAL/HIGH/MEDIUM, by file) | opt-out |
   | Rate Limit | `MISSING_RATE_LIMITING` (LOW) | opt-out |
   | Rate Limit Bypass | `RATE_LIMIT_BYPASS` (HIGH) | opt-out |
   | IDOR/BOLA | `IDOR` (CRITICAL mutating / HIGH otherwise) | opt-in - needs 2 identities |
   | BFLA | `BFLA` (CRITICAL mutating / HIGH otherwise) | opt-in - needs 1+ identity |
   | Mass Assignment / BOPLA | `MASS_ASSIGNMENT` (CRITICAL/HIGH) | opt-in - needs 1+ identity |
   | JWT Weak Secret | `WEAK_JWT_SECRET` (CRITICAL) | opt-in - needs a JWT identity |

   Everything above runs fully anonymous by default; the four opt-in modules need at least one caller identity supplied via `POST /api/scans`'s `identities` field (see [Using the API](#using-the-api)). Every module can be toggled independently with `sentinel.scan.<module>.enabled` (see [Configuration](#configuration)). Each finding carries a severity, the exact evidence that triggered it, and a remediation recommendation; the specific detection mechanics, heuristics, and edge cases for each module are documented in its own class' Javadoc under `src/main/java/com/f3rren/sentinel/attack/`.

3. **Report**: JSON with every finding (endpoint, parameter, payload, evidence, recommendation, severity), a summary broken down **by severity and by issue type**, a numeric risk score alongside the qualitative rating, and a `narrative` field with a human-readable summary.

## Quick start

### From source

```bash
./mvnw spring-boot:run
```

The app starts on `http://localhost:8080`.

### With Docker, against an already-running "victim" app

If the victim already runs via its own `docker-compose`, Sentinel can join the same Docker network to reach it by container name instead of `localhost`:

```bash
cp env.example .env
# open .env and set VICTIM_NETWORK_NAME to the victim's real network name
# (find it with: docker network ls)
docker compose up -d --build
```

Sentinel will be reachable at `http://localhost:8088`. Details and troubleshooting are in the comments of `docker-compose.yml` and `env.example`. `src/` is bind-mounted into the container, so after a code change `docker compose restart sentinel` picks it up in a few seconds - no image rebuild needed. Defaults are conservative for repeated local iteration: `GET`-only (`SENTINEL_SCAN_ALLOWED_HTTP_METHODS`) so a scan never mutates data, and `DEBUG` HTTP logging (`SENTINEL_LOG_HTTP_LEVEL`). Widen either in `.env` once needed.

**Fully automatic scan**: set `SENTINEL_SCAN_AUTO_TARGET_URL` in `.env` to the victim's URL and Sentinel scans it on its own once reachable, no manual request needed:

```bash
curl http://localhost:8088/api/scans/latest
```

## Using the API

**Start a scan**

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "http://localhost:9090"}'
```

**Optional: identities for the opt-in modules**

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://localhost:9090",
    "identities": {
      "a": { "header": "Authorization", "value": "Bearer <tokenForUserA>" },
      "b": { "header": "Authorization", "value": "Bearer <tokenForUserB>" }
    }
  }'
```

Sentinel never generates or discovers these tokens - supply ones already valid for the target. IDOR needs both `a` and `b`; BFLA, Mass Assignment, and JWT Weak Secret need only one (`a`, falling back to `b`).

Response (example):

```json
{
  "id": "…",
  "targetUrl": "http://localhost:9090",
  "endpointsDiscovered": 3,
  "endpointsTested": 3,
  "openApiSpecUrl": null,
  "findings": [ { "module": "sql-injection", "type": "SQL_INJECTION_ERROR_BASED", "description": "...", "recommendation": "...", "occurrences": [ { "severity": "CRITICAL", "endpointUrl": "...", "...": "..." } ] } ],
  "summary": {
    "totalFindings": 1,
    "overallRisk": "CRITICAL",
    "riskScore": 40,
    "possiblyRateLimited": false,
    "countsBySeverity": { "...": 0 },
    "countsByType": { "SQL_INJECTION_ERROR_BASED": 1, "SQL_INJECTION_BOOLEAN_BASED": 0, "MISSING_AUTHENTICATION": 0 }
  },
  "narrative": "Investigation of http://localhost:9090 completed in ... Detected 1 vulnerability (overall risk: CRITICAL, risk score: 40): 1 CRITICAL. By type: 1 SQL_INJECTION_ERROR_BASED."
}
```

`findings` is a list of **groups**: every occurrence sharing the same module, type, description, and recommendation collapses into one entry with an `occurrences` array, rather than repeating the same description/recommendation text per endpoint. Each occurrence carries what actually differs: `id`, `severity`, `endpointUrl`, `method`, `parameter`, `payload`, `evidence`. `summary.countsByType`/`countsBySeverity` count every individual occurrence, not groups.

**`summary.possiblyRateLimited`**: a module fuzzing many parameters can by itself trip the target's rate limiter, making later results look clean when they were actually just throttled. Once at least 10 requests were made and 15%+ came back throttled, this flag is set and the `narrative` gets a `WARNING:` caveat - read such a report as "clean among what responded normally," not a clean bill of health.

**Retrieve a previously generated report**

```bash
curl http://localhost:8080/api/scans/{id}
curl http://localhost:8080/api/scans/latest   # the most recent one, manual or automatic
```

**On file**: every completed scan is also saved as JSON in `reports/` (configurable via `sentinel.scan.reports-directory`), named `<timestamp>-<host>-<scanId>.json`. With Docker, the folder is mounted to `./reports` on the host, so files survive `docker compose down`.

## Configuration

Properties in `src/main/resources/application.properties` (overridable via environment variable, e.g. `SENTINEL_SCAN_MAX_ENDPOINTS`):

| Property | Default | Description |
|---|---|---|
| `sentinel.scan.user-agent` | `Sentinel-Scanner/0.1 (+authorized-security-testing)` | User-Agent used on every request to the target |
| `sentinel.scan.request-timeout-ms` | `8000` | Timeout for a single HTTP request |
| `sentinel.scan.connect-timeout-ms` | `5000` | Connection timeout |
| `sentinel.scan.max-endpoints` | `25` | Maximum number of endpoints attacked per scan |
| `sentinel.scan.reports-directory` | `reports` | Folder where every report is also saved as a JSON file. Empty to disable file persistence |
| `sentinel.scan.allowed-http-methods` | `GET,POST,PUT,PATCH,DELETE` | Only endpoints with these methods get attacked. E.g. `GET` for a scan that never writes |
| `sentinel.scan.auto-target-url` | _(empty)_ | If set, an automatic scan runs against this URL on startup |
| `sentinel.scan.auto-scan-max-attempts` | `20` | Reachability attempts against the target before giving up on the auto-scan |
| `sentinel.scan.auto-scan-retry-delay-ms` | `3000` | Wait between one attempt and the next |
| `sentinel.scan.<module>.enabled` | `true` (`false` for the 4 opt-in modules) | Per-module on/off switch - see the module table above for names |
| `sentinel.scan.brute-force.max-attempts` | `8` | Credential pairs tried per login-shaped endpoint |
| `sentinel.scan.rate-limit.burst-size` | `130` | Requests fired at each `GET` endpoint before concluding no throttling kicked in - must exceed the target's real capacity to be meaningful |

Module property names follow the table: `sql-injection`, `missing-authentication`, `brute-force`, `security-misconfiguration`, `xss`, `data-exposure`, `verbose-error-disclosure`, `actuator-exposure`, `sensitive-file-exposure`, `rate-limit`, `rate-limit-bypass`, `idor`, `bfla`, `mass-assignment`, `jwt-weak-secret`.

## Risk metric

Besides the list of findings, `summary` answers three questions:

- **`countsBySeverity` / `overallRisk`** - how bad is the worst problem found (INFO → CRITICAL).
- **`countsByType`** - how many problems per issue type (one `VulnerabilityType` per module row in the table above), useful once several modules are active.
- **`riskScore`** - a weighted sum (CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0) that distinguishes *volume* at equal `overallRisk` (1 vs. 20 CRITICAL findings share a rating but not a score). A heuristic for comparing successive scans of the same target, not a CVSS or "official" score.

## Development

```bash
./mvnw test   # runs the whole suite
```

## Stack

Java 17, Spring Boot, Jsoup (HTML parsing), Jackson (OpenAPI parsing). Scans run synchronously; reports are kept in memory for retrieval by id during the app's lifetime, and are also persisted as JSON files under `reports/` (see [Using the API](#using-the-api)).
