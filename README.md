# Sentinel

Sentinel is an **automated security testing** tool: given an application's address (e.g. `localhost:8080`), it discovers the exposed endpoints and launches automated attacks to find vulnerabilities, returning a report with severity and remediation guidance.

> **Intended use**: only against applications you are authorized to security-test (your own projects, staging environments, an authorized pentest target). Do not point it at third-party systems without explicit consent.

## What it does today

1. **Endpoint discovery**, in two phases:
   - **OpenAPI/Swagger** (preferred phase): tries to read a spec at `/v3/api-docs`, `/v2/api-docs`, `/swagger.json`, `/openapi.json`, etc. If the target is an API gateway aggregating multiple services (springdoc `swagger-config` or springfox `swagger-resources`), it follows the aggregation and fetches every downstream service's spec. When an operation documents a JSON `requestBody` (typical of POST/PUT/PATCH), it also generates a type-aware sample body (resolving `$ref`s against `components/schemas`: integers as numbers, booleans as booleans, strings with a consistent format), so the endpoint receives a request it can actually process instead of immediately rejecting it with 415/400 for a missing or wrongly-shaped body. Required properties are always populated; optional ones are populated too unless they carry a `pattern` constraint or are an array/object - values a generic sample can't safely guess without risking a validation failure that an absent field would otherwise skip. Fields with no format/enum/pattern constraint get a random, clearly-synthetic `sentinel-<token>` value rather than a plain word like "test" - easy to tell apart from real user data and to grep for in the target's logs/database afterward.
   - **HTML crawling**: if no spec is found (or in addition to it), it parses the target's page for links with a query string and forms, merging them (deduplicated) with whatever Swagger already found.
2. **Attack**, two modules:
   - **SQL Injection**: both error-based (fingerprinting MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, and JDBC/Hibernate error messages) and boolean-based/blind (heuristic on injected true/false conditions). A response throttled by the target's own rate limiting (HTTP 429) on either side of the true/false comparison is treated as inconclusive rather than a signal, since it reflects Sentinel's own request volume, not the application's query logic.
   - **Missing Authentication**: flags endpoints that respond successfully (2xx) to a request carrying no credentials at all (Sentinel never sends an authentication header). A 401/403 response is treated as proof that authentication is enforced (no finding); any other status (400/404/5xx) is inconclusive and ignored. Thanks to the JSON body generated from the OpenAPI schema, this now also works for POST/PUT/PATCH endpoints that require a body - previously they almost always returned 415 (inconclusive), now they can receive a real response. This is deliberately narrower than a true IDOR/BOLA test (which would need two distinct authenticated identities to compare - a concept Sentinel doesn't have yet): it only answers "does this endpoint require authentication at all?".
3. **Report**: JSON with every finding (endpoint, parameter, payload, evidence, recommendation, severity), a summary broken down **by severity and by issue type**, a numeric risk score alongside the qualitative rating, and a `narrative` field with a human-readable summary (in Italian).

Modules planned for future iterations: XSS, IDOR/BOLA with multiple identities, brute force against authentication endpoints.

## Quick start

### From source

```bash
./mvnw spring-boot:run
```

The app starts on `http://localhost:8080`.

### With Docker, against an already-running "victim" app

If the victim already runs via its own `docker-compose`, Sentinel can join the same Docker network to reach it by container name instead of `localhost`:

```bash
cp .env.example .env
# open .env and set VICTIM_NETWORK_NAME to the victim's real network name
# (find it with: docker network ls)
docker compose up -d --build
```

Sentinel will be reachable at `http://localhost:8088`. Details and troubleshooting are in the comments of `docker-compose.yml` and `.env.example`.

**Fully automatic scan (zero manual commands)**: if you also set `SENTINEL_SCAN_AUTO_TARGET_URL` in `.env` to the victim's URL (e.g. `http://api-gateway:8080`), Sentinel waits on its own for the target to respond and launches the scan on container startup, with no manual request needed. The result can be checked at any time with:

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

Response (example):

```json
{
  "id": "…",
  "targetUrl": "http://localhost:9090",
  "endpointsDiscovered": 3,
  "endpointsTested": 3,
  "openApiSpecUrl": null,
  "findings": [ { "type": "SQL_INJECTION_ERROR_BASED", "severity": "CRITICAL", "...": "..." } ],
  "summary": {
    "totalFindings": 1,
    "overallRisk": "CRITICAL",
    "riskScore": 40,
    "countsBySeverity": { "...": 0 },
    "countsByType": { "SQL_INJECTION_ERROR_BASED": 1, "SQL_INJECTION_BOOLEAN_BASED": 0, "MISSING_AUTHENTICATION": 0 }
  },
  "narrative": "Investigazione su http://localhost:9090 completata in ... Rilevate 1 vulnerabilità (rischio complessivo: CRITICAL, punteggio di rischio: 40): 1 CRITICAL. Per tipologia: 1 SQL_INJECTION_ERROR_BASED."
}
```

**Retrieve a previously generated report**

```bash
curl http://localhost:8080/api/scans/{id}
curl http://localhost:8080/api/scans/latest   # the most recent one, manual or automatic
```

**On file**: every completed scan is also saved as JSON in `reports/` (inside the project, configurable via `sentinel.scan.reports-directory`), named `<timestamp>-<host>-<scanId>.json` - useful for keeping, comparing, or versioning results without querying the API. With Docker, the folder is mounted to `./reports` on the host (see `docker-compose.yml`), so the files survive `docker compose down`.

## Configuration

Properties in `src/main/resources/application.properties` (overridable via environment variable too, e.g. `SENTINEL_SCAN_MAX_ENDPOINTS`):

| Property | Default | Description |
|---|---|---|
| `sentinel.scan.user-agent` | `Sentinel-Scanner/0.1 (+authorized-security-testing)` | User-Agent used on every request to the target |
| `sentinel.scan.request-timeout-ms` | `8000` | Timeout for a single HTTP request |
| `sentinel.scan.connect-timeout-ms` | `5000` | Connection timeout |
| `sentinel.scan.max-endpoints` | `25` | Maximum number of endpoints attacked per scan |
| `sentinel.scan.reports-directory` | `reports` | Folder where every report is also saved as a JSON file. Empty to disable file persistence |
| `sentinel.scan.allowed-http-methods` | `GET,POST,PUT,PATCH,DELETE` | Only endpoints with these methods get attacked (discovery still finds all of them). E.g. `GET` to guarantee a scan that never touches anything in writing |
| `sentinel.scan.auto-target-url` | _(empty)_ | If set, an automatic scan runs against this URL on startup, zero manual commands |
| `sentinel.scan.auto-scan-max-attempts` | `20` | Reachability attempts against the target before giving up on the auto-scan |
| `sentinel.scan.auto-scan-retry-delay-ms` | `3000` | Wait between one attempt and the next |
| `sentinel.scan.sql-injection.enabled` | `true` | Enables/disables the SQL injection module. When `false`, the module isn't even instantiated |
| `sentinel.scan.missing-authentication.enabled` | `true` | Enables/disables the Missing Authentication module |

Every future attack module (XSS, IDOR/BOLA, brute force, ...) will follow the same `sentinel.scan.<module>.enabled` convention.

## Risk metric

Besides the list of findings, `summary` answers three different questions:

- **`countsBySeverity` / `overallRisk`** - how bad is the worst problem found (INFO → CRITICAL).
- **`countsByType`** - how many problems for each issue type (`SQL_INJECTION_ERROR_BASED`, `SQL_INJECTION_BOOLEAN_BASED`, `MISSING_AUTHENTICATION`, ...), useful once more than one module is active and you want to know what to focus on.
- **`riskScore`** - a numeric score (weighted sum: CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0) that distinguishes the *volume* of problems at equal `overallRisk`: 1 CRITICAL and 20 CRITICAL share the same `overallRisk`, but a very different score. It's a heuristic meant for comparing successive scans of the same target, not a CVSS or an "official" score.

## Development

```bash
./mvnw test   # runs the whole suite
```

## Stack

Java 17, Spring Boot, Jsoup (HTML parsing), Jackson (OpenAPI parsing). Scans run synchronously; reports are kept in memory for retrieval by id during the app's lifetime, and are also persisted as JSON files under `reports/` (see [Using the API](#using-the-api)).
